package missing_authentication

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "missing-authentication",
		Title:       "Missing Authentication",
		Description: "Ativos técnicos (especialmente sistemas multilocatários) devem autenticar as solicitações recebidas quando o ativo processa ou armazena dados confidenciais. ",
		Impact:      "Se esse risco não for mitigado, os invasores poderão acessar ou modificar dados confidenciais de maneira não autenticada.",
		ASVS:        "V2 - Authentication Verification Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		Action:      "Autenticação de solicitações de entrada",
		Mitigation: "Aplique um método de autenticação ao ativo técnico. Para proteger dados altamente confidenciais, considere " +
			"o uso de autenticação de dois fatores para usuários humanos.",
		Check:    "As recomendações da folha de dicas vinculada e do capítulo ASVS referenciado são aplicadas ?",
		Function: model.Architecture,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "Ativos técnicos dentro do escopo (exceto " + model.LoadBalancer.String() + ", " + model.ReverseProxy.String() + ", " + model.ServiceRegistry.String() + ", " + model.WAF.String() + ", " + model.IDS.String() + ", e " + model.IPS.String() + " e chamadas em processo) devem autenticar as solicitações recebidas quando o ativo processa ou armazena " +
			"dados sensíveis. Esse é especialmente o caso para todos os ativos multilocatários (mesmo aqueles não confidenciais).",
		RiskAssessment: "A classificação de risco (médio ou alto) " +
			"depende da sensibilidade dos dados enviados pelo link de comunicação. Os chamadores de monitoramento estão isentos desse risco.",
		FalsePositives: "Ativos técnicos que não processam solicitações de funcionalidade ou dados vinculados aos usuários finais (clientes)" +
			"podem ser considerados falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        306,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technology == model.LoadBalancer ||
			technicalAsset.Technology == model.ReverseProxy || technicalAsset.Technology == model.ServiceRegistry || technicalAsset.Technology == model.WAF || technicalAsset.Technology == model.IDS || technicalAsset.Technology == model.IPS {
			continue
		}
		if technicalAsset.HighestConfidentiality() >= model.Confidential ||
			technicalAsset.HighestIntegrity() >= model.Critical ||
			technicalAsset.HighestAvailability() >= model.Critical ||
			technicalAsset.MultiTenant {
			// check each incoming data flow
			commLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, commLink := range commLinks {
				caller := model.ParsedModelRoot.TechnicalAssets[commLink.SourceId]
				if caller.Technology.IsUnprotectedCommsTolerated() || caller.Type == model.Datastore {
					continue
				}
				highRisk := commLink.HighestConfidentiality() == model.StrictlyConfidential ||
					commLink.HighestIntegrity() == model.MissionCritical
				lowRisk := commLink.HighestConfidentiality() <= model.Internal &&
					commLink.HighestIntegrity() == model.Operational
				impact := model.MediumImpact
				if highRisk {
					impact = model.HighImpact
				} else if lowRisk {
					impact = model.LowImpact
				}
				if commLink.Authentication == model.NoneAuthentication && !commLink.Protocol.IsProcessLocal() {
					risks = append(risks, CreateRisk(technicalAsset, commLink, commLink, "", impact, model.Likely, false, Category()))
				}
			}
		}
	}
	return risks
}

func CreateRisk(technicalAsset model.TechnicalAsset, incomingAccess, incomingAccessOrigin model.CommunicationLink, hopBetween string,
	impact model.RiskExploitationImpact, likelihood model.RiskExploitationLikelihood, twoFactor bool, category model.RiskCategory) model.Risk {
	factorString := ""
	if twoFactor {
		factorString = "Two-Factor "
	}
	if len(hopBetween) > 0 {
		hopBetween = "forwarded via <b>" + hopBetween + "</b> "
	}
	risk := model.Risk{
		Category:               category,
		Severity:               model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing " + factorString + "Authentication</b> covering communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + model.ParsedModelRoot.TechnicalAssets[incomingAccessOrigin.SourceId].Title + "</b> " + hopBetween +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + incomingAccess.Id + "@" + model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
