package unnecessary_communication_link

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unnecessary-communication-link",
		Title: "Unnecessary Communication Link",
		Description: "Quando um link de comunicação técnica não envia ou recebe quaisquer ativos de dados, isso é " +
			"um indicador para um link de comunicação desnecessário (ou para um modelo incompleto).",
		Impact:                     "Se esse risco não for mitigado, os invasores podem ser capazes de direcionar links de comunicação desnecessários.",
		ASVS:                       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:                     "Redução da superfície de ataque",
		Mitigation:                 "Tente evitar usar links de comunicação técnica que não enviem ou recebam nada.",
		Check:                      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:                   model.Architecture,
		STRIDE:                     model.ElevationOfPrivilege,
		DetectionLogic:             "Links técnicos de comunicação técnica de ativos técnicos no escopo não enviando ou recebendo quaisquer ativos de dados.",
		RiskAssessment:             model.LowSeverity.String(),
		FalsePositives:             "Geralmente não falsos positivos, pois isso parece um modelo incompleto.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		for _, commLink := range technicalAsset.CommunicationLinks {
			if len(commLink.DataAssetsSent) == 0 && len(commLink.DataAssetsReceived) == 0 {
				if !technicalAsset.OutOfScope || !model.ParsedModelRoot.TechnicalAssets[commLink.TargetId].OutOfScope {
					risks = append(risks, createRisk(technicalAsset, commLink))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, commLink model.CommunicationLink) model.Risk {
	title := "<b>Link de comunicação desnecessária</b> intitulada <b>" + commLink.Title + "</b> no ativo técnico <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(model.Unlikely, model.LowImpact),
		ExploitationLikelihood:          model.Unlikely,
		ExploitationImpact:              model.LowImpact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: commLink.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + commLink.Id + "@" + technicalAsset.Id
	return risk
}
