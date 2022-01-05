package dos_risky_access_across_trust_boundary

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "dos-risky-access-across-trust-boundary",
		Title: "DoS-risky Access Across Trust-Boundary",
		Description: "Ativos acessados através dos limites de confiança com classificação de disponibilidade crítica ou de missão crítica " +
			"estão mais sujeitos a riscos de negação de serviço (DoS).",
		Impact:     "Se esse risco permanecer inalterado, os invasores podem perturbar a disponibilidade de partes importantes do sistema.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
		Action:     "Anti-DoS Measures",
		Mitigation: "Aplique técnicas anti-DoS, como limitação e/ou bloqueio de carga por cliente com cotas. " +
			"Também para rotas de acesso de manutenção, considere a aplicação de uma VPN em vez de interfaces acessíveis ao público. " +
			"Geralmente, a aplicação de redundância no ativo técnico de destino reduz o risco de DoS.",
		Check:    "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas? ",
		Function: model.Operations,
		STRIDE:   model.DenialOfService,
		DetectionLogic: "Ativos técnicos dentro do escopo (excluding " + model.LoadBalancer.String() + ") com " +
			"classificação de disponibilidade de " + model.Critical.String() + " ou superior, que tem fluxos de dados de entrada em um " +
			"network trust-boundary (excluindo o uso do " + model.DevOps.String() + ").",
		RiskAssessment: "Combinando ativos técnicos com classificação de disponibilidade " +
			"do " + model.Critical.String() + " ou superiores são " +
			"no " + model.LowSeverity.String() + " risco. Quando a classificação de disponibilidade é " +
			model.MissionCritical.String() + " e nem uma VPN nem filtro IP para o fluxo de dados de entrada nem redundância " +
			"para o ativo é aplicado, a classificação de risco é considerada " + model.MediumSeverity.String() + ".", // TODO reduce also, when data-flow authenticated and encrypted?
		FalsePositives:             "Quando as operações de destino acessadas não consomem tempo ou recursos",
		ModelFailurePossibleReason: false,
		CWE:                        400,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology != model.LoadBalancer &&
			technicalAsset.Availability >= model.Critical {
			for _, incomingAccess := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId]
				if sourceAsset.Technology.IsTrafficForwarding() {
					// Now try to walk a call chain up (1 hop only) to find a caller's caller used by human
					callersCommLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[sourceAsset.Id]
					for _, callersCommLink := range callersCommLinks {
						risks = checkRisk(technicalAsset, callersCommLink, sourceAsset.Title, risks)
					}
				} else {
					risks = checkRisk(technicalAsset, incomingAccess, "", risks)
				}
			}
		}
	}
	return risks
}

func checkRisk(technicalAsset model.TechnicalAsset, incomingAccess model.CommunicationLink, hopBetween string, risks []model.Risk) []model.Risk {
	if incomingAccess.IsAcrossTrustBoundaryNetworkOnly() &&
		!incomingAccess.Protocol.IsProcessLocal() && incomingAccess.Usage != model.DevOps {
		highRisk := technicalAsset.Availability == model.MissionCritical &&
			!incomingAccess.VPN && !incomingAccess.IpFiltered && !technicalAsset.Redundant
		risks = append(risks, createRisk(technicalAsset, incomingAccess, hopBetween,
			model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId], highRisk))
	}
	return risks
}

func createRisk(techAsset model.TechnicalAsset, dataFlow model.CommunicationLink, hopBetween string,
	clientOutsideTrustBoundary model.TechnicalAsset, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky {
		impact = model.MediumImpact
	}
	if len(hopBetween) > 0 {
		hopBetween = " forwarded via <b>" + hopBetween + "</b>"
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood: model.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Denial-of-Service</b> risky access of <b>" + techAsset.Title + "</b> by <b>" + clientOutsideTrustBoundary.Title +
			"</b> via <b>" + dataFlow.Title + "</b>" + hopBetween,
		MostRelevantTechnicalAssetId:    techAsset.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + techAsset.Id + "@" + clientOutsideTrustBoundary.Id + "@" + dataFlow.Id
	return risk
}
