package server_side_request_forgery

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "server-side-request-forgery",
		Title: "Server-Side Request Forgery (SSRF)",
		Description: "Quando um sistema de servidor (i.e. não um cliente) está acessando outros sistemas de servidor via protocolos da Web típicos " +
			"Server-Side Request Forgery (SSRF) ou Local-File-Inclusion (LFI) ou Remote-File-Inclusion (RFI) Os riscos podem surgir. ",
		Impact:     "Se este risco for ignorado, os invasores poderão acessar serviços confidenciais ou arquivos de componentes acessíveis por rede, modificando chamadas de saída dos componentes afetados.",
		ASVS:       "V12 - File and Resources Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
		Action:     "SSRF Prevention",
		Mitigation: "Tente evitar a construção do URL de destino de saída com valores controláveis pelo chamador.Como alternativa, use um mapeamento (Whitelist) ao acessar URLs de saída em vez de criá-los, incluindo chamador " +
			"Valores controláveis. " +
			"Quando um produto de terceiros é usado em vez de um software desenvolvido sob medida, verifique se o produto aplica a atenuação adequada e garanta um nível de patch razoável.",
		Check:          "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:       model.Development,
		STRIDE:         model.InformationDisclosure,
		DetectionLogic: "Sistemas não-cliente dentro do escopo que acessam (usando links de comunicação de saída) alvos com protocolo HTTP ou HTTPS.",
		RiskAssessment: "A classificação de risco (baixo ou médio) depende da sensibilidade dos ativos de dados a receber via protocolos da web de " +
			"alvos dentro do mesmo limite de confiança da rede, bem como sobre a sensibilidade dos ativos de dados recebidos por meio de protocolos da web do próprio ativo alvo. " +
			"Além disso, para ambientes baseados em nuvem, o impacto da exploração é pelo menos médio, pois os serviços de back-end da nuvem podem ser atacados via SSRF. ",
		FalsePositives: "Os servidores que não enviam solicitações da web de saída podem ser considerados " +
			"como falsos positivos após revisão.",
		ModelFailurePossibleReason: false,
		CWE:                        918,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technology.IsClient() || technicalAsset.Technology == model.LoadBalancer {
			continue
		}
		for _, outgoingFlow := range technicalAsset.CommunicationLinks {
			if outgoingFlow.Protocol.IsPotentialWebAccessProtocol() {
				risks = append(risks, createRisk(technicalAsset, outgoingFlow))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, outgoingFlow model.CommunicationLink) model.Risk {
	target := model.ParsedModelRoot.TechnicalAssets[outgoingFlow.TargetId]
	title := "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>" + technicalAsset.Title + "</b> server-side web-requesting " +
		"the target <b>" + target.Title + "</b> via <b>" + outgoingFlow.Title + "</b>"
	impact := model.LowImpact
	// check by the target itself (can be in another trust-boundary)
	if target.HighestConfidentiality() == model.StrictlyConfidential {
		impact = model.MediumImpact
	}
	// check all potential attack targets within the same trust boundary (accessible via web protocols)
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, potentialTargetAsset := range model.ParsedModelRoot.TechnicalAssets {
		if technicalAsset.IsSameTrustBoundaryNetworkOnly(potentialTargetAsset.Id) {
			for _, commLinkIncoming := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[potentialTargetAsset.Id] {
				if commLinkIncoming.Protocol.IsPotentialWebAccessProtocol() {
					uniqueDataBreachTechnicalAssetIDs[potentialTargetAsset.Id] = true
					if potentialTargetAsset.HighestConfidentiality() == model.StrictlyConfidential {
						impact = model.MediumImpact
					}
				}
			}
		}
	}
	// adjust for cloud-based special risks
	if impact == model.LowImpact && model.ParsedModelRoot.TrustBoundaries[technicalAsset.GetTrustBoundaryId()].Type.IsWithinCloud() {
		impact = model.MediumImpact
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key, _ := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	likelihood := model.Likely
	if outgoingFlow.Usage == model.DevOps {
		likelihood = model.Unlikely
	}
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: outgoingFlow.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id + "@" + target.Id + "@" + outgoingFlow.Id
	return risk
}
