package unchecked_deployment

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unchecked-deployment",
		Title: "Unchecked Deployment",
		Description: "Para cada componente do pipeline de construção, riscos de implantação não verificados podem surgir quando o pipeline de construção " +
			"não inclui práticas recomendadas DevSecOps estabelecidas. Varredura de práticas recomendadas de DevSecOps como parte de pipelines de CI / CD para " +
			"vulnerabilidades em código-fonte ou código de bytes, dependências, camadas de contêiner e dinamicamente em relação a sistemas de teste em execução. " +
			"Existem várias ferramentas de código aberto e comerciais nas categorias DAST, SAST e IAST.",
		Impact: "Se este risco permanecer inalterado, vulnerabilidades em software desenvolvido sob medida ou em suas dependências " +
			"pode não ser identificado durante os ciclos de implantação contínua.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Aplicar as melhores práticas DevSecOps e usar ferramentas de varredura para identificar vulnerabilidades no código-fonte ou byte," +
			"dependências, camadas de contêiner e, opcionalmente, também por meio de varreduras dinâmicas em sistemas de teste em execução.",
		Check:          "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:       model.Architecture,
		STRIDE:         model.Tampering,
		DetectionLogic: "Todos os ativos técnicos relevantes para o desenvolvimento.",
		RiskAssessment: "A classificação de risco depende da classificação mais alta dos ativos técnicos e ativos de dados processados por alvos de recebimento de implantação.",
		FalsePositives: "Quando o pipeline de construção não cria nenhum componente de software, pode ser considerado um falso positivo " +
			"após revisão individual.",
		ModelFailurePossibleReason: false,
		CWE:                        1127,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if technicalAsset.Technology.IsDevelopmentRelevant() {
			risks = append(risks, createRisk(technicalAsset))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset) model.Risk {
	title := "<b>Unchecked Deployment</b> risk at <b>" + technicalAsset.Title + "</b>"
	// impact is depending on highest rating
	impact := model.LowImpact
	// data breach at all deployment targets
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, codeDeploymentTargetCommLink := range technicalAsset.CommunicationLinks {
		if codeDeploymentTargetCommLink.Usage == model.DevOps {
			for _, dataAssetID := range codeDeploymentTargetCommLink.DataAssetsSent {
				// it appears to be code when elevated integrity rating of sent data asset
				if model.ParsedModelRoot.DataAssets[dataAssetID].Integrity >= model.Important {
					// here we've got a deployment target which has its data assets at risk via deployment of backdoored code
					uniqueDataBreachTechnicalAssetIDs[codeDeploymentTargetCommLink.TargetId] = true
					targetTechAsset := model.ParsedModelRoot.TechnicalAssets[codeDeploymentTargetCommLink.TargetId]
					if targetTechAsset.HighestConfidentiality() >= model.Confidential ||
						targetTechAsset.HighestIntegrity() >= model.Critical ||
						targetTechAsset.HighestAvailability() >= model.Critical {
						impact = model.MediumImpact
					}
					break
				}
			}
		}
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key, _ := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	// create risk
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Possible,
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
