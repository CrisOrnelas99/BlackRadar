// Package dto defines request and response data transfer objects for the API.
package dto

// CVELookupResponse exposes the safe NVD CVE details returned by the backend.
type CVELookupResponse struct {
	CVEID          string `json:"cveId"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	PublishedAt    string `json:"publishedAt"`
	LastModifiedAt string `json:"lastModifiedAt"`
	NVDURL         string `json:"nvdUrl"`
}
