import os
from datetime import datetime
from src.backend.config import SENSITIVE_FILES

# Try importing ML libraries; provide safe fallback mock models if import fails
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    import sklearn
    SKLEARN_AVAILABLE = True if NUMPY_AVAILABLE else False
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    TORCH_AVAILABLE = True if NUMPY_AVAILABLE else False
except ImportError:
    TORCH_AVAILABLE = False


# Feature size is 6: [hour, day_of_week, event_type, process_name_hash, is_sensitive, trust_score]
FEATURE_SIZE = 6

def extract_features(event_data, trust_score=100):
    """
    Extracts a normalized numeric feature vector from a FIM event.
    Returns a float list of size FEATURE_SIZE.
    """
    try:
        t = datetime.fromisoformat(event_data.get("timestamp", datetime.now().isoformat()))
    except Exception:
        t = datetime.now()
        
    hour = t.hour / 23.0
    day_of_week = t.weekday() / 6.0
    
    evt_map = {"CREATED": 0.0, "MODIFIED": 0.33, "DELETED": 0.66, "MOVED": 1.0}
    evt_type = evt_map.get(event_data.get("event_type", "MODIFIED"), 0.33)
    
    # Convert process name to numerical hash between 0 and 1
    proc_name = event_data.get("process_name", "explorer.exe").lower()
    proc_hash = (abs(hash(proc_name)) % 1000) / 1000.0
    
    # Check if target file is classified as sensitive
    file_name = os.path.basename(event_data.get("file_path", ""))
    is_sensitive = 1.0 if file_name in SENSITIVE_FILES else 0.0
    
    # Normalise Trust Score
    trust_norm = trust_score / 100.0

    return [hour, day_of_week, evt_type, proc_hash, is_sensitive, trust_norm]

class IsolationForestModel:
    def __init__(self):
        self.model = None
        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)

    def train(self, X):
        if not SKLEARN_AVAILABLE or self.model is None:
            return
        self.model.fit(X)

    def predict_anomaly_score(self, x):
        """
        Predicts anomaly score. 0.0 is normal, 1.0 is highly anomalous.
        """
        if not SKLEARN_AVAILABLE or self.model is None:
            # Simple heuristic fallback
            # High score if sensitive file, low trust score, or suspicious process
            score = 0.1
            if x[4] > 0.8: score += 0.3  # Sensitive file
            if x[5] < 0.7: score += 0.4  # Low trust score
            if x[3] > 0.8: score += 0.2  # Arbitrary mock process anomaly
            return min(1.0, score)

        # Isolation forest returns scores: decision_function returns negative for anomalies
        # We normalize: decision_function is in range [-0.5, 0.5] approx.
        raw_score = self.model.decision_function([x])[0]
        # Map: low/negative values -> high anomaly score (towards 1.0)
        # high positive values -> low anomaly score (towards 0.0)
        norm_score = 1.0 - (raw_score + 0.5) # Shift and invert
        return float(np.clip(norm_score, 0.0, 1.0))


if TORCH_AVAILABLE:
    class PyTorchAE(nn.Module):
        def __init__(self, input_dim):
            super().__init__()
            # Encoder
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 8),
                nn.ReLU(),
                nn.Linear(8, 3),
                nn.ReLU()
            )
            # Decoder
            self.decoder = nn.Sequential(
                nn.Linear(3, 8),
                nn.ReLU(),
                nn.Linear(8, input_dim),
                nn.Sigmoid()
            )

        def forward(self, x):
            latent = self.encoder(x)
            reconstructed = self.decoder(latent)
            return reconstructed
else:
    PyTorchAE = None

class AutoencoderModel:
    def __init__(self):
        self.model = None
        self.max_error = 1.0  # Dynamic normalizer
        if TORCH_AVAILABLE:
            self.model = PyTorchAE(FEATURE_SIZE)
            self.criterion = nn.MSELoss()
            self.optimizer = optim.Adam(self.model.parameters(), lr=0.01)

    def train(self, X, epochs=50):
        if not TORCH_AVAILABLE or self.model is None:
            return
            
        X_tensor = torch.tensor(X, dtype=torch.float32)
        
        self.model.train()
        for epoch in range(epochs):
            self.optimizer.zero_grad()
            outputs = self.model(X_tensor)
            loss = self.criterion(outputs, X_tensor)
            loss.backward()
            self.optimizer.step()
            
        # Calibrate max error on training data to normalize predictions later
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            errors = torch.mean((reconstructed - X_tensor) ** 2, dim=1).numpy()
            self.max_error = float(np.percentile(errors, 95))
            if self.max_error == 0:
                self.max_error = 1.0

    def predict_anomaly_score(self, x):
        """
        Returns anomaly score based on reconstruction error.
        """
        if not TORCH_AVAILABLE or self.model is None:
            # Safe fallback matching Isolation Forest logic
            score = 0.1
            if x[4] > 0.8: score += 0.35
            if x[5] < 0.7: score += 0.45
            return min(1.0, score)
            
        self.model.eval()
        with torch.no_grad():
            x_tensor = torch.tensor([x], dtype=torch.float32)
            reconstructed = self.model(x_tensor)
            error = float(self.criterion(reconstructed, x_tensor).item())
            
        # Normalize relative to max baseline error
        score = error / self.max_error
        return float(np.clip(score, 0.0, 1.0))


# Global model orchestrator
class AnomalyDetector:
    def __init__(self):
        self.if_model = IsolationForestModel()
        self.ae_model = AutoencoderModel()
        self.train_baseline_models()

    def train_baseline_models(self):
        """
        Generates normal behavior baseline data and trains the ML models.
        Normal behavior is defined as:
        - Workday hours (e.g. 9 AM - 6 PM)
        - Non-sensitive files
        - Common trusted processes (explorer.exe, python.exe)
        - High runtime trust (90 - 100)
        """
        if not NUMPY_AVAILABLE:
            return
            
        # Generate 200 normal samples
        np.random.seed(42)
        normal_data = []
        for _ in range(200):
            hour = np.random.uniform(9, 17) / 23.0  # Business hours
            day = np.random.randint(0, 5) / 6.0  # Mon-Fri
            evt = 0.33  # Mostly modified
            proc = (abs(hash(np.random.choice(["explorer.exe", "python.exe"]))) % 1000) / 1000.0
            sens = 0.0  # Non-sensitive files
            trust = np.random.uniform(95, 100) / 100.0  # Trusted state
            
            normal_data.append([hour, day, evt, proc, sens, trust])
            
        X = np.array(normal_data)
        
        try:
            self.if_model.train(X)
        except Exception:
            pass
            
        try:
            self.ae_model.train(X)
        except Exception:
            pass

    def compute_anomaly_scores(self, event_data, trust_score=100):
        """
        Computes anomaly score using both Isolation Forest and Autoencoder.
        Returns a dictionary with scores and average anomaly score.
        """
        x = extract_features(event_data, trust_score)
        
        try:
            if_score = self.if_model.predict_anomaly_score(x)
        except Exception:
            if_score = 0.1
            
        try:
            ae_score = self.ae_model.predict_anomaly_score(x)
        except Exception:
            ae_score = 0.1
            
        mean_score = (if_score + ae_score) / 2.0
        
        return {
            "isolation_forest_score": round(if_score, 3),
            "autoencoder_score": round(ae_score, 3),
            "anomaly_score": round(mean_score, 3)
        }
