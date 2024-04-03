package rules

import (
	"fmt"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// Reference: https://huggingface.co/docs/hub/security-tokens
//
// Old tokens have the prefix `api_`, however, I am not sure it's worth detecting them as that would be high noise.
// https://huggingface.co/docs/api-inference/quicktour
func HuggingFaceAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "huggingface-access-token",
		Description: "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.",
		Regex:       regexp.MustCompile(`(?:^|[\\'"` + "`" + ` >=:])(hf_[a-zA-Z]{34})(?:$|[\\'"` + "`" + ` <])`),

		Entropy: 1,
		Keywords: []string{
			"hf_",
		},
	}

	// validate
	tps := []string{
 
 
 
 
 
 
 
 
 
 
 
 
 
 
		`                    change_dir(cwd)
 
 
		`# HuggingFace API Token https://huggingface.co/settings/tokens
		HUGGINGFACE_API_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,`,
	}
	return validate(r, tps, fps)
}

// Will be deprecated Aug 1st, 2023.
func HuggingFaceOrganizationApiToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "huggingface-organization-api-token",
		Description: "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.",
		Regex:       regexp.MustCompile(`(?:^|[\\'"` + "`" + ` >=:\(,)])(api_org_[a-zA-Z]{34})(?:$|[\\'"` + "`" + ` <\),])`),

		Entropy: 2,
		Keywords: []string{
			"api_org_",
		},
	}

	// validate
	tps := []string{
		"`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`",
		`\"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\"`,
		`(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)`,
		`def test_private_space(self):
        io = gr.load(`,
		`"news_train_dataset = datasets.load_dataset('nlpHakdang/aihub-news30k',  data_files = \"train_news_text.csv\", use_auth_token='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')\n",`,
		fmt.Sprintf("api_org_%s", secrets.NewSecret(`[a-zA-Z]{34}`)),
	}
		`public static final String API_ORG_EXIST = "APIOrganizationExist";`,
		`const api_org_controller = require('../../controllers/api/index').organizations;`,
		`def test_internal_api_org_inclusion_with_href(api_name, href, expected, monkeypatch, called_with):
		`    def _api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a(self, method, url, body, headers):
        return httplib.OK, body, headers, httplib.responses[httplib.OK]`,
		`<p>You should see a token <code>hf_xxxxx</code> (old tokens are <code>api_XXXXXXXX</code> or <code>api_org_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</code>).</p>`,
		`  From Hugging Face docs:
		You should see a token hf_xxxxx (old tokens are api_XXXXXXXX or api_org_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx).
 
 
 
 
