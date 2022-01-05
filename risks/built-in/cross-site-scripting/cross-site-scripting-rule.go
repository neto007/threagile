package cross_site_scripting

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "cross-site-scripting",
		Title: "Cross-Site Scripting (XSS)",
		Description: "Para cada aplicativo da web, podem surgir riscos de Cross-Site Scripting (XSS). Em termos " +
			"do nível de risco geral, leve em consideração outros aplicativos em execução no mesmo domínio.",
		Impact:     "Se esse risco permanecer inalterado, os invasores podem acessar as sessões individuais das vítimas e roubar ou modificar os dados do usuário.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		Action:     "XSS Prevention",
		Mitigation: "Tente codificar todos os valores enviados de volta ao navegador e também lidar com manipulações de DOM de maneira segura " +
			"para evitar XSS baseado em DOM. " +
			"Quando um produto de terceiros é usado em vez de um software desenvolvido sob medida, verifique se o produto aplica a atenuação adequada e garanta um nível de patch razoável.",
		Check:          "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:       model.Development,
		STRIDE:         model.Tampering,
		DetectionLogic: "In-scope web applications.",
		RiskAssessment: "A classificação de risco depende da sensibilidade dos dados processados ou armazenados no aplicativo da web.",
		FalsePositives: "Quando o ativo técnico " +
			"não é acessado por meio de um componente semelhante ao navegador (ou seja, não por um usuário humano iniciando a solicitação que " +
			"passa por todos os componentes até atingir o aplicativo da web), isso pode ser considerado um falso positivo.",
		ModelFailurePossibleReason: false,
		CWE:                        79,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technology.IsWebApplication() { // TODO: also mobile clients or rich-clients as long as they use web-view...
			continue
		}
		risks = append(risks, createRisk(technicalAsset))
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Cross-Site Scripting (XSS)</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.HighImpact
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood:       model.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
