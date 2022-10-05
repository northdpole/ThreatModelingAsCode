from diagrams.programming.flowchart import Action
import os


class ThreatModel:
    Threats = []
    Mitigations = []
    Interfaces = {}
    NodeName = ""
    Remediated = []

    def diagram(self):
        raise NotImplementedError("you really should implement this")

    def as_node(self):
        """Return whole threat model as a node that can be included in another threat model"""
        if len(self.Threats):
            return Action(
                label=self.NodeName,
                xlabel=self.render_threats(self.Threats, self.Remediated),
            )
        else:
            return Action(label=self.NodeName)

    # todo: ensure you can link to this from another diagram
    def add_external_interface(self, name):
        self.Interfaces[name] = Action(name, style="invis")

    def render_threats(self, threats=[], remediated_threats=[]):
        if os.environ.get("NOSHOWTHREATS"):
            return
        self.Threats = set(self.Threats)
        [self.Threats.add(t) for t in threats]

        self.Remediated = set(self.Remediated)
        [self.Remediated.add(r) for r in remediated_threats]

        res = '< <table border="1">'
        for t in threats:
            if t not in remediated_threats:
                res += '<tr><td color="red" align="text">' + t + "</td></tr>"
            else:
                res += '<tr><td align="text">' + t + "</td></tr>"
        res += "</table> >"
        return res
