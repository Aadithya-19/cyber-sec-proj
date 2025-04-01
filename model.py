from river import anomaly, compose, preprocessing, drift, tree
import logging

class AdaptiveAttackDetector:
    def __init__(self, threshold=0.0):
        # With threshold set to 0, every log is classified using the classifier.
        self.threshold = threshold
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.detectors = [
            compose.Pipeline(preprocessing.StandardScaler(), anomaly.HalfSpaceTrees(n_trees=10, seed=1)),
            compose.Pipeline(preprocessing.StandardScaler(), anomaly.HalfSpaceTrees(n_trees=15, seed=2)),
            compose.Pipeline(preprocessing.StandardScaler(), anomaly.HalfSpaceTrees(n_trees=20, seed=3)),
        ]
        self.drift_detector = drift.ADWIN()
        self.classifier = compose.Pipeline(
            preprocessing.StandardScaler(),
            tree.HoeffdingTreeClassifier()
        )
        self.response_memory = {}
        self.logger.info("AdaptiveAttackDetector initialized with threshold: %s", threshold)

    def train_classifier(self, X, y):
        for x, y_i in zip(X, y):
            try:
                self.classifier.learn_one(x, y_i)
                self.logger.debug("Classifier trained on sample with label %s", y_i)
            except Exception as e:
                self.logger.error("Error training classifier with features %s: %s", x, e)

    def process_log(self, features):
        try:
            if not isinstance(features, dict):
                self.logger.error("Features must be a dictionary, got: %s", type(features))
                return 0.0, 'unknown'

            scores = []
            for i, detector in enumerate(self.detectors):
                try:
                    score = detector.score_one(features)
                    scores.append(score)
                except Exception as e:
                    self.logger.error("Detector %s failed to score: %s", i, e)
            anomaly_score = sum(scores) / len(scores) if scores else 0.0
            self.logger.info("Anomaly score: %.2f", anomaly_score)

            for i, detector in enumerate(self.detectors):
                try:
                    detector.learn_one(features)
                except Exception as e:
                    self.logger.error("Detector %s failed to learn: %s", i, e)

            try:
                self.drift_detector.update(anomaly_score)
                if self.drift_detector.drift_detected:
                    self.logger.warning("Concept drift detected")
            except Exception as e:
                self.logger.error("Drift detector failed: %s", e)

            try:
                attack_type = self.classifier.predict_one(features)
                if attack_type is None or attack_type.lower() == "normal":
                    attack_type = "generic_attack"
                self.logger.info("Attack detected: type %s, score %.2f", attack_type, anomaly_score)
            except Exception as e:
                self.logger.error("Classifier prediction failed with features %s: %s", features, e)
                attack_type = "generic_attack"

            return anomaly_score, attack_type
        except Exception as e:
            self.logger.error("Unexpected error in process_log: %s", e)
            return 0.0, 'unknown'   