package container_baseimage_backdooring

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "container-baseimage-backdooring",
		Title: "Container Base Image Backdooring",
		Description: "Quando um ativo técnico é construído usando tecnologias de contêiner, os riscos de backdooring da imagem de base podem surgir onde " +
			"imagens de base e outras camadas usadas contêm componentes vulneráveis ou backdoors." +
			"<br><br>por example: <a href=\"https://techcrunch.com/2018/06/15/tainted-crypto-mining-containers-pulled-from-docker-hub/\">https://techcrunch.com/2018/06/15/tainted-crypto-mining-containers-pulled-from-docker-hub/</a>",
		Impact:     "Se esse risco não for mitigado, os invasores podem persistir profundamente no sistema de destino, executando o código em contêineres implantados.",
		ASVS:       "V10 - Malicious Code Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
		Action:     "Container Infrastructure Hardening",
		Mitigation: "Aplique a proteção de todas as infraestruturas de contêiner (consulte, por exemplo, os <i> CIS-Benchmarks para Docker e Kubernetes </i> e o <i> Docker Bench para Segurança </i>). " +
			"Use apenas imagens de base confiáveis dos fornecedores originais, verifique as assinaturas digitais e aplique as melhores práticas de criação de imagens. " +
			"Considere também o uso de imagens de base <i> Distroless </i> do Google ou imagens de base muito pequenas. " +
			"Execute regularmente varreduras de imagens de contêiner com ferramentas que verificam as camadas em busca de componentes vulneráveis.",
		Check:          "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:       model.Operations,
		STRIDE:         model.Tampering,
		DetectionLogic: "Ativos técnicos no escopo executados como contêineres.",
		RiskAssessment: "A classificação de risco depende da sensibilidade do próprio ativo técnico e dos ativos de dados.",
		FalsePositives: "Imagens de base de contêineres totalmente confiáveis (ou seja, revisadas e assinadas criptograficamente ou semelhantes) podem ser consideradas " +
			"como falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        912,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Machine == model.Container {
			risks = append(risks, createRisk(technicalAsset))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Container Base Image Backdooring</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.HighImpact
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
