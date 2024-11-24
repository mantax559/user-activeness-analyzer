from abc import ABC, abstractmethod

class SystemAnalyzer(ABC):
    @abstractmethod
    def collect_event_logs(self):
        pass

    @abstractmethod
    def collect_network_activity(self):
        pass