package missing_identity_provider_isolation

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-identity-provider-isolation",
		Title: "Missing Identity Provider Isolation",
		Description: "Ativos de provedor de identidade altamente confidenciais e seus armazenamentos de dados de identidade devem ser isolados de outros ativos " +
			"por sua própria segmentação de rede trust-boundary (" + model.ExecutionEnvironment.String() + " limites não contam como isolamento de rede)",
		Impact: "Se este risco não for mitigado, os invasores que atacam com sucesso outros componentes do sistema podem ter um caminho fácil para " +
			"ativos de provedor de identidade altamente confidenciais e seus armazenamentos de dados de identidade, uma vez que não são separados por segmentação de rede.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Network Segmentation",
		Mitigation: "Aplique um limite de confiança de segmentação de rede em torno dos ativos de provedor de identidade altamente confidenciais e seus armazenamentos de dados de identidade.",
		Check:      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:   model.Operations,
		STRIDE:     model.ElevationOfPrivilege,
		DetectionLogic: "Ativos de provedor de identidade no escopo e seus armazenamentos de dados de identidade " +
			"quando cercado por outros ativos (não relacionados à identidade) ou (sem um network trust-boundary no meio). " +
			"Este risco é especialmente prevalente quando outros ativos não relacionados à identidade estão dentro do mesmo ambiente de execução (ou seja, mesmo banco de dados ou mesmo servidor de aplicativos).",
		RiskAssessment: "O padrão é " + model.HighImpact.String() + " impacto. O impacto é aumentado para " + model.VeryHighImpact.String() + " quando o ativo está faltando " +
			"trust-boundary protection é classificado como " + model.StrictlyConfidential.String() + " ou " + model.MissionCritical.String() + ".",
		FalsePositives: "Quando todos os ativos dentro do trust-boundary da segmentação de rede são reforçados e protegidos da mesma forma como se todos fossem" +
			"provedores de identidade com dados de maior sensibilidade.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope && technicalAsset.Technology.IsIdentityRelated() {
			moreImpact := technicalAsset.Confidentiality == model.StrictlyConfidential ||
				technicalAsset.Integrity == model.MissionCritical ||
				technicalAsset.Availability == model.MissionCritical
			sameExecutionEnv := false
			createRiskEntry := false
			// now check for any other same-network assets of non-identity-related types
			for sparringAssetCandidateId, _ := range model.ParsedModelRoot.TechnicalAssets { // so inner loop again over all assets
				if technicalAsset.Id != sparringAssetCandidateId {
					sparringAssetCandidate := model.ParsedModelRoot.TechnicalAssets[sparringAssetCandidateId]
					if !sparringAssetCandidate.Technology.IsIdentityRelated() && !sparringAssetCandidate.Technology.IsCloseToHighValueTargetsTolerated() {
						if technicalAsset.IsSameExecutionEnvironment(sparringAssetCandidateId) {
							createRiskEntry = true
							sameExecutionEnv = true
						} else if technicalAsset.IsSameTrustBoundaryNetworkOnly(sparringAssetCandidateId) {
							createRiskEntry = true
						}
					}
				}
			}
			if createRiskEntry {
				risks = append(risks, createRisk(technicalAsset, moreImpact, sameExecutionEnv))
			}
		}
	}
	return risks
}

func createRisk(techAsset model.TechnicalAsset, moreImpact bool, sameExecutionEnv bool) model.Risk {
	impact := model.HighImpact
	likelihood := model.Unlikely
	others := "<b>in the same network segment</b>"
	if moreImpact {
		impact = model.VeryHighImpact
	}
	if sameExecutionEnv {
		likelihood = model.Likely
		others = "<b>in the same execution environment</b>"
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing Identity Provider Isolation</b> to further encapsulate and protect identity-related asset <b>" + techAsset.Title + "</b> against unrelated " +
			"lower protected assets " + others + ", which might be easier to compromise by attackers",
		MostRelevantTechnicalAssetId: techAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{techAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + techAsset.Id
	return risk
}
