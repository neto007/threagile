package missing_file_validation

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "missing-file-validation",
		Title:       "Missing File Validation",
		Description: "Quando um ativo técnico aceita arquivos, esses arquivos de entrada devem ser validados estritamente quanto ao nome do arquivo e tipo.",
		Impact:      "Se esse risco não for mitigado, os invasores podem fornecer arquivos maliciosos ao aplicativo.",
		ASVS:        "V12 - File and Resources Verification Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
		Action:      "File Validation",
		Mitigation: "Filtre por extensão de arquivo e descarte (se possível) o nome fornecido. Coloque na lista de permissões os tipos de arquivo aceitos " +
			"e determine o tipo MIME no lado do servidor (por exemplo, via \"Apache Tika\"ou verificações semelhantes). Se o arquivo for recuperável por " +
			"usuários finais e/ou funcionários de backoffice, considerem realizar varreduras de malware popular (se os arquivos puderem ser recuperados muito mais tarde do que eles " +
			"foram carregados, aplique também uma nova varredura de malware durante a recuperação para fazer a varredura com assinaturas mais recentes de malware popular). Também aplique " +
			"limites no tamanho máximo do arquivo para evitar cenários de negação de serviço.",
		Check:          "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:       model.Development,
		STRIDE:         model.Spoofing,
		DetectionLogic: "Ativos técnicos dentro do escopo com código desenvolvido sob medida que aceita formatos de dados de arquivo.",
		RiskAssessment: "A classificação de risco depende da sensibilidade do próprio ativo técnico e dos ativos de dados processados e armazenados.",
		FalsePositives: "Arquivos totalmente confiáveis (ou seja, assinados criptograficamente ou semelhantes) podem ser considerados " +
			"como falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        434,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.CustomDevelopedParts {
			continue
		}
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == model.File {
				risks = append(risks, createRisk(technicalAsset))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Missing File Validation</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.LowImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.VeryLikely, impact),
		ExploitationLikelihood:       model.VeryLikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
