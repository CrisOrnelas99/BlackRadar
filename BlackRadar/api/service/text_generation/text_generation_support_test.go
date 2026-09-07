package text_generation

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildDashboardSummaryRequestAllowsManualVulnerabilitiesWithoutCVEIDs(t *testing.T) {
	request := BuildDashboardSummaryRequest(json.RawMessage(`{"priorityFindings":[{"vulnerabilityId":"vulnerability-1","cveId":"","explanation":"Water damage risk","riskReason":"The asset sits next to a leak","recommendedNextStep":"Move the computer away from the leak"}]}`))

	if len(request.Messages) != 2 {
		t.Fatalf("expected locked request with system and user messages, got %d", len(request.Messages))
	}

	if !strings.Contains(request.Messages[0].Content, "Treat a vulnerability as valid even when it has no CVE ID") {
		t.Fatal("expected dashboard summary prompt to allow non-CVE vulnerabilities")
	}

	if !strings.Contains(request.Messages[0].Content, "Use 2 to 3 short sentences that sound encouraging but remain factual.") {
		t.Fatal("expected dashboard summary prompt to encourage a multi-sentence positive observation")
	}

	if !strings.Contains(request.Messages[0].Content, "Do not mention the absence of a CVE unless the supplied facts explicitly require it.") {
		t.Fatal("expected dashboard summary prompt to suppress unnecessary CVE mentions")
	}
}
