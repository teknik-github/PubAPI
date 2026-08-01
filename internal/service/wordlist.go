package service

// defaultSubs is a compact, high-signal subdomain wordlist for quick recon.
// It favors breadth of common services over exhaustiveness to keep requests fast.
var defaultSubs = []string{
	"www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "ns3",
	"dns", "dns1", "dns2", "mx", "mx1", "email", "cpanel", "whm", "autodiscover",
	"admin", "administrator", "portal", "dashboard", "panel", "manage", "control",
	"api", "api1", "api2", "apiv1", "apiv2", "rest", "graphql", "gateway",
	"dev", "development", "staging", "stage", "test", "testing", "qa", "uat", "sandbox",
	"demo", "beta", "alpha", "preview", "next", "canary",
	"app", "apps", "mobile", "m", "web", "www2", "www3",
	"blog", "news", "forum", "community", "help", "support", "docs", "wiki", "kb",
	"shop", "store", "cart", "checkout", "payment", "pay", "billing", "invoice",
	"cdn", "static", "assets", "img", "images", "media", "files", "download", "downloads",
	"vpn", "remote", "ssh", "sftp", "git", "gitlab", "github", "jenkins", "ci", "cd",
	"jira", "confluence", "bitbucket", "svn", "repo", "registry", "docker", "harbor",
	"db", "database", "mysql", "postgres", "mongo", "redis", "sql", "phpmyadmin", "adminer",
	"monitor", "monitoring", "grafana", "kibana", "prometheus", "status", "health", "metrics",
	"auth", "sso", "login", "signin", "account", "accounts", "id", "identity", "oauth",
	"secure", "vault", "kms", "internal", "intranet", "corp", "private", "backup", "backups",
	"cloud", "aws", "azure", "gcp", "s3", "storage", "bucket",
	"crm", "erp", "hr", "finance", "sales", "marketing", "analytics", "stats", "data",
	"video", "stream", "live", "chat", "voip", "sip", "conference", "meet",
	"old", "new", "legacy", "archive", "tmp", "temp", "beta2", "v1", "v2", "v3",
}

// DefaultSubdomains returns a copy of the built-in subdomain wordlist.
func DefaultSubdomains() []string {
	out := make([]string, len(defaultSubs))
	copy(out, defaultSubs)
	return out
}
