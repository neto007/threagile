package search_query_injection

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "search-query-injection",
		Title: "Search-Query Injection",
		Description: "Quando um servidor de mecanismo de pesquisa é acessado, os riscos de injeção de consulta de pesquisa podem surgir." +
			"<br><br>Veja por exemploo <a href=\"https://github.com/veracode-research/solr-injection\">https://github.com/veracode-research/solr-injection</a> e " +
			"<a href=\"https://github.com/veracode-research/solr-injection/blob/master/slides/DEFCON-27-Michael-Stepankin-Apache-Solr-Injection.pdf\">https://github.com/veracode-research/solr-injection/blob/master/slides/DEFCON-27-Michael-Stepankin-Apache-Solr-Injection.pdf</a> " +
			"Para mais detalhes (aqui relacionados ao Solr, mas em geral, mostrando o tópico das injeções de consulta de pesquisa).",
		Impact: "Se este risco permanecer desconhecido, os invasores podem ser capazes de ler mais dados do índice de pesquisa e " +
			"eventualmente, escalar ainda mais para uma penetração mais profunda no sistema por meio de execuções de código.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
		Action:     "Search-Query Injection Prevention",
		Mitigation: "Tente usar bibliotecas que codifiquem corretamente os metacaracteres de consulta de pesquisa em pesquisas e não exponha o " +
			"consulta não filtrada para o chamador. " +
			"Quando um produto de terceiros é usado em vez de um software desenvolvido sob medida, verifique se o produto aplica a atenuação adequada e garanta um nível de patch razoável.",
		Check:          "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:       model.Development,
		STRIDE:         model.Tampering,
		DetectionLogic: "Clientes dentro do escopo acessando servidores de mecanismo de pesquisa por meio de protocolos de acesso de pesquisa típicos.",
		RiskAssessment: "A classificação de risco depende da sensibilidade do próprio servidor do mecanismo de pesquisa e dos ativos de dados processados ou armazenados.",
		FalsePositives: "As consultas do motor do servidor por valores de pesquisa que não consistem em partes controláveis pelo chamador podem ser consideradas " +
			"como falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        74,
	}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.Technology == model.SearchEngine || technicalAsset.Technology == model.SearchIndex {
			incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, incomingFlow := range incomingFlows {
				if model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
					continue
				}
				if incomingFlow.Protocol == model.HTTP || incomingFlow.Protocol == model.HTTPS ||
					incomingFlow.Protocol == model.BINARY || incomingFlow.Protocol == model.BINARY_encrypted {
					likelihood := model.VeryLikely
					if incomingFlow.Usage == model.DevOps {
						likelihood = model.Likely
					}
					risks = append(risks, createRisk(technicalAsset, incomingFlow, likelihood))
				}
			}
		}
	}
	return risks
}

func SupportedTags() []string {
	return []string{}
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink, likelihood model.RiskExploitationLikelihood) model.Risk {
	caller := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Search Query Injection</b> risk at <b>" + caller.Title + "</b> against search engine server <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.HighImpact
	} else if technicalAsset.HighestConfidentiality() <= model.Internal && technicalAsset.HighestIntegrity() == model.Operational {
		impact = model.LowImpact
	}
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           model.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
