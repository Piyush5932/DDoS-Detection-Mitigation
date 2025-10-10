import numpy as np

class DDoSDetector:
    def __init__(self):
        print("DDoS Detector initialized")
        self.model = None
        
    def train(self, X, y):
        print("Training model with sample data")
        # Simplified training for testing
        self.model = "dummy_model"
        return True
        
    def predict(self, features):
        # For testing, just return 1 (attack) if sum of features > threshold
        if np.sum(features) > 10:
            return 1  # Attack
        return 0  # Normal
        
    def load_model(self, model_path=None):
        # Simplified model loading for testing
        print("Loading model (dummy)")
        self.model = "dummy_model"
        return True