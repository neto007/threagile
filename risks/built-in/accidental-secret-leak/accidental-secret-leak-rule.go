package accidental_secret_leak

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "accidental-secret-leak",
		Title: "Accidental Secret Leak",
		Description: "Repositórios de código fonte (incluindo seus históricos), bem como registros de artefatos podem acidentalmente conter segredos como " +
			"senhas registradas ou empacotadas, tokens de API, certificados, chaves criptográficas, etc.",
		Impact: "Se este risco não for mitigado, os invasores que têm acesso aos repositórios de código-fonte afetados ou registros de artefatos podem " +
			"encontrar segredos com check-in acidental.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Estabeleça medidas de prevenção de check-in acidental ou pacote de segredos em repositórios de código-fonte " +
			"e registros de artefatos. Isso começa usando bons arquivos .gitignore e .dockerignore, mas não para por aí. " +
			"Veja, por exemplo, ferramentas como <i> \"git-secrets \" ou \"Talisman \" </i> para ter medidas preventivas de verificação de segredos. " +
			"Considere também verificar regularmente seus repositórios em busca de segredos registrados acidentalmente usando ferramentas de verificação como <i>\"gitleaks\" ou \"gitrob\" </i>.",
		Check:                      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:                   model.Operations,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Repositórios de código-fonte e registros de artefatos dentro do escopo",
		RiskAssessment:             "A classificação de risco depende da sensibilidade do próprio ativo técnico e dos ativos de dados processados e armazenados.",
		FalsePositives:             "Normalmente não há falsos positivos.",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func SupportedTags() []string {
	return []string{"git", "nexus"}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !techAsset.OutOfScope &&
			(techAsset.Technology == model.SourcecodeRepository || techAsset.Technology == model.ArtifactRegistry) {
			var risk model.Risk
			if techAsset.IsTaggedWithAny("git") {
				risk = createRisk(techAsset, "Git", "Git Leak Prevention")
			} else {
				risk = createRisk(techAsset, "", "")
			}
			risks = append(risks, risk)
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, prefix, details string) model.Risk {
	if len(prefix) > 0 {
		prefix = " (" + prefix + ")"
	}
	title := "<b>Accidental Secret Leak" + prefix + "</b> risk at <b>" + technicalAsset.Title + "</b>"
	if len(details) > 0 {
		title += ": <u>" + details + "</u>"
	}
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() >= model.Confidential ||
		technicalAsset.HighestIntegrity() >= model.Critical ||
		technicalAsset.HighestAvailability() >= model.Critical {
		impact = model.MediumImpact
	}
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.HighImpact
	}
	// create risk
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
