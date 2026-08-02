// Package securityaction owns the bounded operation vocabulary used by
// security controls. The concrete operation types prevent handlers from
// supplying ad hoc strings while this package remains dependency-free.
package securityaction

type MailLimitProfile uint8

const (
	MailLimitInvalid MailLimitProfile = iota
	MailLimitSave
	MailLimitTest
	MailLimitActivate
	MailLimitRollback
	MailLimitDisable
)

type descriptor struct {
	bucket       string
	metricGroup  string
	metricAction string
	mailProfile  MailLimitProfile
}

type RateLimitOperation interface {
	rateLimitDescriptor() descriptor
}

type AccountOperation uint8

const (
	AccountRegister AccountOperation = iota + 1
	AccountPasswordReset
	AccountEmailVerification
	AccountPendingEmailVerification
	AccountEmailChange
)

var accountDescriptors = [...]descriptor{
	AccountRegister:                 {bucket: "register", metricGroup: "account_action", metricAction: "register"},
	AccountPasswordReset:            {bucket: "password-reset", metricGroup: "account_action", metricAction: "password_reset"},
	AccountEmailVerification:        {bucket: "email-verification", metricGroup: "account_action", metricAction: "email_verification"},
	AccountPendingEmailVerification: {bucket: "pending-email-verification", metricGroup: "account_action", metricAction: "pending_email_verification"},
	AccountEmailChange:              {bucket: "email-change", metricGroup: "account_action", metricAction: "email_change"},
}

func (operation AccountOperation) rateLimitDescriptor() descriptor {
	return descriptorAt(accountDescriptors[:], int(operation))
}

type MediaOperation uint8

const (
	MediaAvatarUpload MediaOperation = iota + 1
	MediaAvatarDelete
	MediaClientLogoUpload
	MediaClientLogoDelete
)

var mediaDescriptors = [...]descriptor{
	MediaAvatarUpload:     {bucket: "avatar-upload", metricGroup: "media", metricAction: "avatar_upload"},
	MediaAvatarDelete:     {bucket: "avatar-delete", metricGroup: "media", metricAction: "avatar_delete"},
	MediaClientLogoUpload: {bucket: "client-logo-upload", metricGroup: "media", metricAction: "client_logo_upload"},
	MediaClientLogoDelete: {bucket: "client-logo-delete", metricGroup: "media", metricAction: "client_logo_delete"},
}

func (operation MediaOperation) rateLimitDescriptor() descriptor {
	return descriptorAt(mediaDescriptors[:], int(operation))
}

type MailOperation uint8

const (
	MailCandidateSave MailOperation = iota + 1
	MailCandidateTest
	MailActivate
	MailRollback
	MailDisable
)

var mailDescriptors = [...]descriptor{
	MailCandidateSave: {bucket: "candidate-save", metricGroup: "mail_settings", metricAction: "candidate_save", mailProfile: MailLimitSave},
	MailCandidateTest: {bucket: "candidate-test", metricGroup: "mail_settings", metricAction: "candidate_test", mailProfile: MailLimitTest},
	MailActivate:      {bucket: "activate", metricGroup: "mail_settings", metricAction: "activate", mailProfile: MailLimitActivate},
	MailRollback:      {bucket: "rollback", metricGroup: "mail_settings", metricAction: "rollback", mailProfile: MailLimitRollback},
	MailDisable:       {bucket: "disable", metricGroup: "mail_settings", metricAction: "disable", mailProfile: MailLimitDisable},
}

func (operation MailOperation) rateLimitDescriptor() descriptor {
	return descriptorAt(mailDescriptors[:], int(operation))
}

func (operation MailOperation) LimitProfile() MailLimitProfile {
	return operation.rateLimitDescriptor().mailProfile
}

type CoreOperation uint8

const (
	CoreLogin CoreOperation = iota + 1
	CoreSettingsUpdate
)

var coreDescriptors = [...]descriptor{
	CoreLogin:          {bucket: "login", metricGroup: "login", metricAction: "login"},
	CoreSettingsUpdate: {bucket: "update", metricGroup: "settings", metricAction: "update"},
}

func (operation CoreOperation) rateLimitDescriptor() descriptor {
	return descriptorAt(coreDescriptors[:], int(operation))
}

func Bucket(operation RateLimitOperation) (string, bool) {
	descriptor, ok := describe(operation)
	return descriptor.bucket, ok
}

func RateLimitLabels(operation RateLimitOperation) (group, action string, ok bool) {
	descriptor, ok := describe(operation)
	if !ok {
		return "other", "other", false
	}
	return descriptor.metricGroup, descriptor.metricAction, true
}

func AllRateLimitOperations() []RateLimitOperation {
	operations := make([]RateLimitOperation, 0, len(accountDescriptors)+len(mediaDescriptors)+len(mailDescriptors)+len(coreDescriptors)-4)
	for operation := AccountRegister; operation <= AccountEmailChange; operation++ {
		operations = append(operations, operation)
	}
	for operation := MediaAvatarUpload; operation <= MediaClientLogoDelete; operation++ {
		operations = append(operations, operation)
	}
	for operation := MailCandidateSave; operation <= MailDisable; operation++ {
		operations = append(operations, operation)
	}
	for operation := CoreLogin; operation <= CoreSettingsUpdate; operation++ {
		operations = append(operations, operation)
	}
	return operations
}

func describe(operation RateLimitOperation) (descriptor, bool) {
	if operation == nil {
		return descriptor{}, false
	}
	descriptor := operation.rateLimitDescriptor()
	if descriptor.bucket == "" || descriptor.metricGroup == "" || descriptor.metricAction == "" {
		return descriptor, false
	}
	return descriptor, true
}

func descriptorAt(descriptors []descriptor, index int) descriptor {
	if index <= 0 || index >= len(descriptors) {
		return descriptor{}
	}
	return descriptors[index]
}
