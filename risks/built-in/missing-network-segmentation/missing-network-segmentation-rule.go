package missing_network_segmentation

import (
	"sort"

	"github.com/threagile/threagile/model"
)

const raaLimit = 50

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-network-segmentation",
		Title: "Missing Network Segmentation",
		Description: "Ativos altamente sensíveis e/ou armazenamentos de dados que residem no mesmo segmento de rede que outros " +
			"ativos menos sensíveis (como servidores da web ou sistemas de gerenciamento de conteúdo, etc.) devem ser melhor protegidos " +
			"por um limite de confiança de segmentação de rede.",
		Impact: "Se este risco não for mitigado, os invasores que atacam com sucesso outros componentes do sistema podem ter um caminho fácil para " +
			"alvos mais valiosos, uma vez que não são separados por segmentação de rede.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Network Segmentation",
		Mitigation: "Aplique um limite de confiança de segmentação de rede em torno dos ativos e / ou armazenamentos de dados altamente confidenciais.",
		Check:      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:   model.Operations,
		STRIDE:     model.ElevationOfPrivilege,
		DetectionLogic: "Ativos técnicos no escopo com alta sensibilidade e valores de RAA, bem como armazenamentos de dados " +
			"quando cercado por ativos (without a network trust-boundary in-between) que são do tipo " + model.ClientSystem.String() + ", " +
			model.WebServer.String() + ", " + model.WebApplication.String() + ", " + model.CMS.String() + ", " + model.WebServiceREST.String() + ", " + model.WebServiceSOAP.String() + ", " +
			model.BuildPipeline.String() + ", " + model.SourcecodeRepository.String() + ", " + model.Monitoring.String() + ", ou semelhante e não há conexão direta entre estes " +
			"(portanto, não há necessidade de estar tão perto um do outro).",
		RiskAssessment: "O padrão é risco " + model.LowSeverity.String() + ". O risco aumenta para " + model.MediumSeverity.String() + " quando o ativo está faltando " +
			"trust-boundary proteção é classificada como " + model.StrictlyConfidential.String() + " ou " + model.MissionCritical.String() + ".",
		FalsePositives: "Quando todos os ativos dentro do limite de confiança da segmentação de rede são reforçados e protegidos da mesma forma como se todos fossem " +
			"contendo/processando dados altamente confidenciais.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	keys := make([]string, 0)
	for k, _ := range model.ParsedModelRoot.TechnicalAssets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[key]
		if !technicalAsset.OutOfScope && technicalAsset.Technology != model.ReverseProxy && technicalAsset.Technology != model.WAF && technicalAsset.Technology != model.IDS && technicalAsset.Technology != model.IPS && technicalAsset.Technology != model.ServiceRegistry {
			if technicalAsset.RAA >= raaLimit && (technicalAsset.Type == model.Datastore || technicalAsset.Confidentiality >= model.Confidential ||
				technicalAsset.Integrity >= model.Critical || technicalAsset.Availability >= model.Critical) {
				// now check for any other same-network assets of certain types which have no direct connection
				for _, sparringAssetCandidateId := range keys { // so inner loop again over all assets
					if technicalAsset.Id != sparringAssetCandidateId {
						sparringAssetCandidate := model.ParsedModelRoot.TechnicalAssets[sparringAssetCandidateId]
						if sparringAssetCandidate.Technology.IsLessProtectedType() &&
							technicalAsset.IsSameTrustBoundaryNetworkOnly(sparringAssetCandidateId) &&
							!technicalAsset.HasDirectConnection(sparringAssetCandidateId) &&
							!sparringAssetCandidate.Technology.IsCloseToHighValueTargetsTolerated() {
							highRisk := technicalAsset.Confidentiality == model.StrictlyConfidential ||
								technicalAsset.Integrity == model.MissionCritical || technicalAsset.Availability == model.MissionCritical
							risks = append(risks, createRisk(technicalAsset, highRisk))
							break
						}
					}
				}
			}
		}
	}
	return risks
}

func createRisk(techAsset model.TechnicalAsset, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood: model.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Missing Network Segmentation</b> to further encapsulate and protect <b>" + techAsset.Title + "</b> against unrelated " +
			"lower protected assets in the same network segment, which might be easier to compromise by attackers",
		MostRelevantTechnicalAssetId: techAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{techAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + techAsset.Id
	return risk
}
