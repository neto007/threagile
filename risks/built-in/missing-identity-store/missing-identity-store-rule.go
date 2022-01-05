package missing_identity_store

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-identity-store",
		Title: "Missing Identity Store",
		Description: "A arquitetura modelada não contém um armazenamento de identidade, o que pode ser o risco de um modelo faltar " +
			"ativos críticos (e, portanto, não vendo seus riscos).",
		Impact: "Se este risco não for mitigado, os invasores podem ser capazes de explorar riscos não vistos neste modelo de ameaça no provedor / armazenamento de identidade " +
			"que está faltando no modelo.",
		ASVS:           "V2 - Authentication Verification Requirements",
		CheatSheet:     "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		Action:         "Loja de Identidade",
		Mitigation:     "Inclui um armazenamento de identidade no modelo se o aplicativo tiver um login.",
		Check:          "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:       model.Architecture,
		STRIDE:         model.Spoofing,
		DetectionLogic: "Modelos com fluxos de dados autenticados autorizados por meio da identidade do usuário final sem um armazenamento de identidade dentro do escopo.",
		RiskAssessment: "A classificação de risco depende da sensibilidade dos ativos técnicos autorizados de identidade do usuário final e " +
			"seus ativos de dados processados e armazenados. ",
		FalsePositives: "Modelos que oferecem apenas dados / serviços sem nenhuma necessidade real de autenticação " +
			"podem ser considerados falsos positivos após revisão individual.",
		ModelFailurePossibleReason: true,
		CWE:                        287,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope &&
			(technicalAsset.Technology == model.IdentityStoreLDAP || technicalAsset.Technology == model.IdentityStoreDatabase) {
			// everything fine, no risk, as we have an in-scope identity store in the model
			return risks
		}
	}
	// now check if we have enduser-identity authorized communication links, then it's a risk
	riskIdentified := false
	var mostRelevantAsset model.TechnicalAsset
	impact := model.LowImpact
	for _, id := range model.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		for _, commLink := range technicalAsset.CommunicationLinksSorted() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
			if commLink.Authorization == model.EnduserIdentityPropagation {
				riskIdentified = true
				targetAsset := model.ParsedModelRoot.TechnicalAssets[commLink.TargetId]
				if impact == model.LowImpact {
					mostRelevantAsset = targetAsset
					if targetAsset.HighestConfidentiality() >= model.Confidential ||
						targetAsset.HighestIntegrity() >= model.Critical ||
						targetAsset.HighestAvailability() >= model.Critical {
						impact = model.MediumImpact
					}
				}
				if targetAsset.Confidentiality >= model.Confidential ||
					targetAsset.Integrity >= model.Critical ||
					targetAsset.Availability >= model.Critical {
					impact = model.MediumImpact
				}
				// just for referencing the most interesting asset
				if technicalAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
					mostRelevantAsset = technicalAsset
				}
			}
		}
	}
	if riskIdentified {
		risks = append(risks, createRisk(mostRelevantAsset, impact))
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact) model.Risk {
	title := "<b>Missing Identity Store</b> in the threat model (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
