package push_instead_of_pull_deployment

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "push-instead-of-pull-deployment",
		Title: "Push instead of Pull Deployment",
		Description: "Ao comparar implantações baseadas em push-baseadas em uma perspectiva de segurança, baseada em puxar " +
			"as implantações melhoram a segurança geral das metas de implantação.Toda interface exposta de um sistema de produção para aceitar uma implantação " +
			"aumenta a superfície do ataque do sistema de produção, portanto, uma abordagem baseada em puxar expõe menos superfície de ataque relevante " +
			"interfaces.",
		Impact: "Se este risco for ignorado, os invasores podem ter mais vetores alvo potenciais para ataques, já que a superfície de ataque geral é " +
			"Aumento desnecessariamente.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Tente preferir implantações baseadas em puxar (como ofertas de cenários Gitops) sobre as implantações baseadas em push para reduzir a superfície do ataque do sistema de produção.",
		Check:      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:   model.Architecture,
		STRIDE:     model.Tampering,
		DetectionLogic: "Modelos com componentes de pipeline de construção acessando alvos no escopo de implantação (de maneira não readonly) que " +
			"Não são componentes relacionados a construir.",
		RiskAssessment: "A classificação de risco depende da maior sensibilidade das metas de implantação que executam peças desenvolvidas personalizadas.",
		FalsePositives: "Links de comunicação que não são caminhos de implantação " +
			"podem ser considerados falsos positivos após revisão individual.",
		ModelFailurePossibleReason: true,
		CWE:                        1127,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	impact := model.LowImpact
	for _, buildPipeline := range model.ParsedModelRoot.TechnicalAssets {
		if buildPipeline.Technology == model.BuildPipeline {
			for _, deploymentLink := range buildPipeline.CommunicationLinks {
				targetAsset := model.ParsedModelRoot.TechnicalAssets[deploymentLink.TargetId]
				if !deploymentLink.Readonly && deploymentLink.Usage == model.DevOps &&
					!targetAsset.OutOfScope && !targetAsset.Technology.IsDevelopmentRelevant() && targetAsset.Usage == model.Business {
					if targetAsset.HighestConfidentiality() >= model.Confidential ||
						targetAsset.HighestIntegrity() >= model.Critical ||
						targetAsset.HighestAvailability() >= model.Critical {
						impact = model.MediumImpact
					}
					risks = append(risks, createRisk(buildPipeline, targetAsset, deploymentLink, impact))
				}
			}
		}
	}
	return risks
}

func createRisk(buildPipeline model.TechnicalAsset, deploymentTarget model.TechnicalAsset, deploymentCommLink model.CommunicationLink, impact model.RiskExploitationImpact) model.Risk {
	title := "<b>Push instead of Pull Deployment</b> at <b>" + deploymentTarget.Title + "</b> via build pipeline asset <b>" + buildPipeline.Title + "</b>"
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:          model.Unlikely,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    deploymentTarget.Id,
		MostRelevantCommunicationLinkId: deploymentCommLink.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{deploymentTarget.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + buildPipeline.Id
	return risk
}
