package securityaction

import "testing"

func TestRateLimitCatalogIsCompleteAndUnique(t *testing.T) {
	t.Parallel()
	seenBuckets := make(map[string]struct{})
	seenMetrics := make(map[string]struct{})
	for _, operation := range AllRateLimitOperations() {
		bucket, ok := Bucket(operation)
		if !ok {
			t.Fatalf("catalog contains invalid operation %#v", operation)
		}
		group, action, ok := RateLimitLabels(operation)
		if !ok {
			t.Fatalf("catalog contains operation without metric labels %#v", operation)
		}
		metric := group + ":" + action
		if _, duplicate := seenMetrics[metric]; duplicate {
			t.Fatalf("duplicate metric identity %q", metric)
		}
		seenMetrics[metric] = struct{}{}
		bucketIdentity := group + ":" + bucket
		if _, duplicate := seenBuckets[bucketIdentity]; duplicate {
			t.Fatalf("duplicate bucket identity %q", bucketIdentity)
		}
		seenBuckets[bucketIdentity] = struct{}{}
		if mail, ok := operation.(MailOperation); ok && mail.LimitProfile() == MailLimitInvalid {
			t.Fatalf("mail operation %d has no limit profile", mail)
		}
	}
}

func TestInvalidOperationsHaveNoSecurityIdentity(t *testing.T) {
	t.Parallel()
	invalid := []RateLimitOperation{
		AccountOperation(255), MediaOperation(255), MailOperation(255), CoreOperation(255),
	}
	for _, operation := range invalid {
		if bucket, ok := Bucket(operation); ok || bucket != "" {
			t.Fatalf("invalid operation exposed bucket %q", bucket)
		}
		if group, action, ok := RateLimitLabels(operation); ok || group != "other" || action != "other" {
			t.Fatalf("invalid operation labels = %q/%q valid=%v", group, action, ok)
		}
	}
}
