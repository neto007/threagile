package missing_vault_isolation

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-vault-isolation",
		Title: "Missing Vault Isolation",
		Description: "Ativos de cofre altamente confidenciais e seus armazenamentos de dados devem ser isolados de outros ativos " +
			"por sua própria segmentação de rede trust-boundary (" + model.ExecutionEnvironment.String() + " boundaries não contam como isolamento de rede).",
		Impact: "Se este risco não for mitigado, os invasores que atacam com sucesso outros componentes do sistema podem ter um caminho fácil para " +
			"ativos de cofre altamente confidenciais e seus armazenamentos de dados, uma vez que não são separados por segmentação de rede",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Network Segmentation",
		Mitigation: "Aplique um limite de confiança de segmentação de rede em torno dos ativos de cofre altamente confidenciais e seus armazenamentos de dados.",
		Check:      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:   model.Operations,
		STRIDE:     model.ElevationOfPrivilege,
		DetectionLogic: "In-scope vault assets " +
			"quando cercado por outros ativos (não relacionados ao cofre) (sem um limite de confiança de rede no meio). " +
			"Este risco é especialmente prevalente quando outros ativos não relacionados ao cofre estão no mesmo ambiente de execução (ou seja, mesmo banco de dados ou mesmo servidor de aplicativos).",
		RiskAssessment: "O padrão é " + model.MediumImpact.String() + " impacto. O impacto é aumentado para " + model.HighImpact.String() + " quando o ativo está faltando " +
			"trust-boundary proteção é classificada como " + model.StrictlyConfidential.String() + " ou " + model.MissionCritical.String() + ".",
		FalsePositives: "Quando todos os ativos dentro do limite de confiança da segmentação de rede são reforçados e protegidos da mesma forma como se todos fossem " +
			"cofres com dados de maior sensibilidade.",
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
		if !technicalAsset.OutOfScope && technicalAsset.Technology == model.Vault {
			moreImpact := technicalAsset.Confidentiality == model.StrictlyConfidential ||
				technicalAsset.Integrity == model.MissionCritical ||
				technicalAsset.Availability == model.MissionCritical
			sameExecutionEnv := false
			createRiskEntry := false
			// now check for any other same-network assets of non-vault-related types
			for sparringAssetCandidateId, _ := range model.ParsedModelRoot.TechnicalAssets { // so inner loop again over all assets
				if technicalAsset.Id != sparringAssetCandidateId {
					sparringAssetCandidate := model.ParsedModelRoot.TechnicalAssets[sparringAssetCandidateId]
					if sparringAssetCandidate.Technology != model.Vault && !isVaultStorage(technicalAsset, sparringAssetCandidate) {
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

func isVaultStorage(vault model.TechnicalAsset, storage model.TechnicalAsset) bool {
	return storage.Type == model.Datastore && vault.HasDirectConnection(storage.Id)
}

func createRisk(techAsset model.TechnicalAsset, moreImpact bool, sameExecutionEnv bool) model.Risk {
	impact := model.MediumImpact
	likelihood := model.Unlikely
	others := "<b>in the same network segment</b>"
	if moreImpact {
		impact = model.HighImpact
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
		Title: "<b>Missing Vault Isolation</b> to further encapsulate and protect vault-related asset <b>" + techAsset.Title + "</b> against unrelated " +
			"lower protected assets " + others + ", which might be easier to compromise by attackers",
		MostRelevantTechnicalAssetId: techAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{techAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + techAsset.Id
	return risk
}
