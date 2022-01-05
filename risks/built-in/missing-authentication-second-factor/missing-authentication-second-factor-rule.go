package missing_authentication_second_factor

import (
	"github.com/threagile/threagile/model"
	missing_authentication "github.com/threagile/threagile/risks/built-in/missing-authentication"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-authentication-second-factor",
		Title: "Missing Two-Factor Authentication (2FA)",
		Description: "Ativos técnicos (especialmente sistemas multi-tenant) devem autenticar as solicitações recebidas com " +
			"Autenticação de dois fator (2FA) quando o ativo processa ou armazena dados altamente sensíveis (em termos de confidencialidade, integridade e disponibilidade) e é acessado por humanos.",
		Impact:     "Se este risco for ignorado, os invasores poderão acessar ou modificar dados altamente confidenciais sem autenticação forte.",
		ASVS:       "V2 - Authentication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
		Action:     "Autenticação com o segundo fator (2FA)",
		Mitigation: "Aplique um método de autenticação para o ativo técnico que protege dados altamente sensíveis via " +
			"Autenticação de dois fatores para usuários humanos.",
		Check:    "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function: model.BusinessSide,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "Ativos técnicos dentro do escopo (exceto " + model.LoadBalancer.String() + ", " + model.ReverseProxy.String() + ", " + model.WAF.String() + ", " + model.IDS.String() + ", e " + model.IPS.String() + ") deve autenticar solicitações recebidas via autenticação de dois fatoresores (2FA) " +
			"quando o ativo processa ou armazena dados altamente sensíveis (em termos de confidencialidade, integridade e disponibilidade) e é acessado por um cliente usado por um usuário humano.",
		RiskAssessment: model.MediumSeverity.String(),
		FalsePositives: "Ativos técnicos que não processam solicitações de funcionalidade ou dados vinculados aos usuários finais (clientes) " +
			"podem ser considerados falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        308,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope ||
			technicalAsset.Technology.IsTrafficForwarding() ||
			technicalAsset.Technology.IsUnprotectedCommsTolerated() {
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
				if caller.UsedAsClientByHuman {
					moreRisky := commLink.HighestConfidentiality() >= model.Confidential ||
						commLink.HighestIntegrity() >= model.Critical
					if moreRisky && commLink.Authentication != model.TwoFactor {
						risks = append(risks, missing_authentication.CreateRisk(technicalAsset, commLink, commLink, "", model.MediumImpact, model.Unlikely, true, Category()))
					}
				} else if caller.Technology.IsTrafficForwarding() {
					// Now try to walk a call chain up (1 hop only) to find a caller's caller used by human
					callersCommLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[caller.Id]
					for _, callersCommLink := range callersCommLinks {
						callersCaller := model.ParsedModelRoot.TechnicalAssets[callersCommLink.SourceId]
						if callersCaller.Technology.IsUnprotectedCommsTolerated() || callersCaller.Type == model.Datastore {
							continue
						}
						if callersCaller.UsedAsClientByHuman {
							moreRisky := callersCommLink.HighestConfidentiality() >= model.Confidential ||
								callersCommLink.HighestIntegrity() >= model.Critical
							if moreRisky && callersCommLink.Authentication != model.TwoFactor {
								risks = append(risks, missing_authentication.CreateRisk(technicalAsset, commLink, callersCommLink, caller.Title, model.MediumImpact, model.Unlikely, true, Category()))
							}
						}
					}
				}
			}
		}
	}
	return risks
}
