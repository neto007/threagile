package path_traversal

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "path-traversal",
		Title: "Path-Traversal",
		Description: "Quando um sistema de arquivos é acessado, podem surgir riscos de Traversal de Caminho ou Inclusão de Arquivo Local (LFI)." +
			"A classificação de risco depende da sensibilidade do próprio ativo técnico e dos ativos de dados processados ou armazenados.",
		Impact: "Se esse risco não for mitigado, os invasores poderão ler arquivos confidenciais (dados de configuração, arquivos de chave/credencial, arquivos de implantação, " +
			"arquivos de dados de negócios, etc.) do sistema de arquivos dos componentes afetados.",
		ASVS:       "V12 - File and Resources Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
		Action:     "Path-Traversal Prevention",
		Mitigation: "Antes de acessar o arquivo, verifique se ele reside na pasta esperada e se está na posição " +
			"tipo e nome de arquivo / sufixo. Tente usar um mapeamento, se possível, em vez de acessar diretamente por um nome de arquivo que é " +
			"(parcial ou totalmente) fornecido pelo chamador. " +
			"Quando um produto de terceiros é usado em vez de um software desenvolvido sob medida, verifique se o produto aplica a atenuação adequada e garanta um nível de patch razoável.",
		Check:          "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:       model.Development,
		STRIDE:         model.InformationDisclosure,
		DetectionLogic: "Sistemas de arquivos acessados por chamadores dentro do escopo.",
		RiskAssessment: "A classificação de risco depende da sensibilidade dos dados armazenados dentro do ativo técnico.",
		FalsePositives: "Os acessos a arquivos por nomes de arquivos que não consistem em partes controláveis pelo chamador podem ser considerados " +
			"como falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        22,
	}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.Technology != model.FileServer && technicalAsset.Technology != model.LocalFileSystem {
			continue
		}
		incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			likelihood := model.VeryLikely
			if incomingFlow.Usage == model.DevOps {
				likelihood = model.Likely
			}
			risks = append(risks, createRisk(technicalAsset, incomingFlow, likelihood))
		}
	}
	return risks
}

func SupportedTags() []string {
	return []string{}
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink, likelihood model.RiskExploitationLikelihood) model.Risk {
	caller := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Path-Traversal</b> risk at <b>" + caller.Title + "</b> against filesystem <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential || technicalAsset.HighestIntegrity() == model.MissionCritical {
		impact = model.HighImpact
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
