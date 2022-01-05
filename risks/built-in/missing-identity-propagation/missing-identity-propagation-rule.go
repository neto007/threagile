package missing_identity_propagation

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-identity-propagation",
		Title: "Missing Identity Propagation",
		Description: "Ativos técnicos (especialmente sistemas multilocatários), que geralmente processam dados para usuários finais, devem " +
			"autorizar todas as solicitações com base na identidade do usuário final quando o fluxo de dados for autenticado (ou seja, não público). " +
			"Para usos de DevOps, pelo menos uma autorização de usuário técnico é necessária.",
		Impact: "Se este risco não for mitigado, os invasores poderão acessar ou modificar dados externos após o comprometimento bem-sucedido de um componente dentro " +
			"o sistema devido à falta de verificações de autorização baseadas em recursos",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
		Action:     "Propagação de identidade e autorização baseada em recursos",
		Mitigation: "Ao processar solicitações para usuários finais, se possível, autorize no back-end contra o propagado " +
			"identidade do usuário final. Isso pode ser feito passando JWTs ou tokens semelhantes e verificando-os no back-end " +
			"serviços Para usos DevOps, aplique pelo menos uma autorização de usuário técnico.",
		Check:    "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function: model.Architecture,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "Ativos técnicos semelhantes a serviços no escopo que geralmente processam dados com base em solicitações do usuário final, se autenticados " +
			"(ou seja, não público), deve autorizar as solicitações recebidas com base na identidade do usuário final propagada quando sua classificação for confidencial. " +
			"Esse é especialmente o caso para todos os ativos multilocatários (até mesmo aqueles classificados como menos sensíveis). " +
			"Os usos do DevOps estão isentos desse risco.",
		RiskAssessment: "A classificação de risco (médio ou alto) " +
			"depende da classificação de confidencialidade, integridade e disponibilidade do ativo técnico.",
		FalsePositives: "Ativos técnicos que não processam solicitações de funcionalidade ou dados vinculados aos usuários finais (clientes) " +
			"podem ser considerados falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        284,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.Technology.IsUsuallyProcessingEnduserRequests() &&
			(technicalAsset.Confidentiality >= model.Confidential ||
				technicalAsset.Integrity >= model.Critical ||
				technicalAsset.Availability >= model.Critical ||
				(technicalAsset.MultiTenant &&
					(technicalAsset.Confidentiality >= model.Restricted ||
						technicalAsset.Integrity >= model.Important ||
						technicalAsset.Availability >= model.Important))) {
			// check each incoming authenticated data flow
			commLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, commLink := range commLinks {
				caller := model.ParsedModelRoot.TechnicalAssets[commLink.SourceId]
				if !caller.Technology.IsUsuallyAbleToPropagateIdentityToOutgoingTargets() || caller.Type == model.Datastore {
					continue
				}
				if commLink.Authentication != model.NoneAuthentication &&
					commLink.Authorization != model.EnduserIdentityPropagation {
					if commLink.Usage == model.DevOps && commLink.Authorization != model.NoneAuthorization {
						continue
					}
					highRisk := technicalAsset.Confidentiality == model.StrictlyConfidential ||
						technicalAsset.Integrity == model.MissionCritical ||
						technicalAsset.Availability == model.MissionCritical
					risks = append(risks, createRisk(technicalAsset, commLink, highRisk))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingAccess model.CommunicationLink, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood: model.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Missing Enduser Identity Propagation</b> over communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Title + "</b> " +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + incomingAccess.Id + "@" + model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
