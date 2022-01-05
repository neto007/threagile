package container_platform_escape

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "container-platform-escape",
		Title: "Container Platform Escape",
		Description: "As plataformas de contêiner são alvos especialmente interessantes para invasores, pois hospedam grandes partes de uma infraestrutura de tempo de execução em contêiner. " +
			"Quando não configurados e operados com as melhores práticas de segurança em mente, os invasores podem explorar uma vulnerabilidade dentro de um contêiner e escapar em direção " +
			"a plataforma como usuários altamente privilegiados. Esses cenários podem dar aos invasores recursos para atacar todos os outros contêineres como proprietários da plataforma de contêiner " +
			"(por meio de ataques de escape de contêiner) é igual a possuir todos os contêineres.",
		Impact: "Se este risco não for mitigado, os invasores que comprometeram um contêiner com sucesso (por meio de outras vulnerabilidades) " +
			"pode ser capaz de persistir profundamente no sistema de destino, executando o código em muitos contêineres implantados " +
			"e a própria plataforma de contêiner.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
		Action:     "Container Infrastructure Hardening",
		Mitigation: "Aplicar hardening para todos os container da infrastrutura. " +
			"<p> Veja, por exemplo, os <i> CIS-Benchmarks para Docker e Kubernetes </i> " +
			"bem como o <i>Docker Bench for Security</i> ( <a href=\"https://github.com/docker/docker-bench-security\">https://github.com/docker/docker-bench-security</a> ) " +
			"ou <i>Verificações InSpec para Docker e Kubernetes</i> ( <a href=\"https://github.com/dev-sec/cis-kubernetes-benchmark\">https://github.com/dev-sec/cis-docker-benchmark</a> e <a href=\"https://github.com/dev-sec/cis-kubernetes-benchmark\">https://github.com/dev-sec/cis-kubernetes-benchmark</a> ). " +
			"Use apenas imagens de base confiáveis, verifique as assinaturas digitais e aplique as melhores práticas de criação de imagens. Considere também o uso de imagens de base <b> Distroless </i> do Google ou de outras imagens de base muito pequenas. " +
			"Aplique isolamento de namespace e afinidade de nod para separar pods uns dos outros em termos de acesso e nós do mesmo estilo que você separa dados.",
		Check:          "As recomendações da folha de dicas vinculada e do capítulo ASVS referenciado são aplicadas?",
		Function:       model.Operations,
		STRIDE:         model.ElevationOfPrivilege,
		DetectionLogic: "In-scope container platforms.",
		RiskAssessment: "A classificação de risco depende da sensibilidade do próprio ativo técnico e dos ativos de dados processados e armazenados.",
		FalsePositives: "Plataformas de contêiner que não executam partes da arquitetura de destino podem ser consideradas " +
			"como falsos positivos após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{"docker", "kubernetes", "openshift"}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology == model.ContainerPlatform {
			risks = append(risks, createRisk(technicalAsset))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Container Platform Escape</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.MediumImpact
	if technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
		technicalAsset.HighestIntegrity() == model.MissionCritical ||
		technicalAsset.HighestAvailability() == model.MissionCritical {
		impact = model.HighImpact
	}
	// data breach at all container assets
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for id, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		if techAsset.Machine == model.Container {
			dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, id)
		}
	}
	// create risk
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
