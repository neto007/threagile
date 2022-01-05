package missing_build_infrastructure

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-build-infrastructure",
		Title: "Missing Build Infrastructure",
		Description: "A arquitetura modelada não contém uma infraestrutura de construção (devops-client, sourcecode-repo, build-pipeline, etc.), " +
			"o que pode ser o risco de um modelo perder ativos críticos (e, portanto, não ver seus riscos). " +
			"Se a arquitetura contém partes desenvolvidas de forma personalizada, o pipeline onde o código é desenvolvido " +
			"e construído precisa fazer parte do modelo.",
		Impact: "Se este risco não for mitigado, os invasores podem explorar riscos não vistos neste modelo de ameaça devido ao " +
			"componentes críticos de infraestrutura de construção ausentes no modelo",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Construir enrijecimento de dutos",
		Mitigation: "Inclui a infraestrutura de construção no modelo.",
		Check:      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:   model.Architecture,
		STRIDE:     model.Tampering,
		DetectionLogic: "Modelos com partes desenvolvidas personalizadas no escopo sem desenvolvimento no escopo (criação de código) e infraestrutura de construção " +
			"componentes (devops-client, sourcecode-repo, build-pipeline, etc.).",
		RiskAssessment: "A classificação de risco depende da sensibilidade mais alta dos ativos no escopo que executam peças desenvolvidas de maneira personalizada.",
		FalsePositives: "Modelos sem peças desenvolvidas sob medida " +
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
	hasCustomDevelopedParts, hasBuildPipeline, hasSourcecodeRepo, hasDevOpsClient := false, false, false, false
	impact := model.LowImpact
	var mostRelevantAsset model.TechnicalAsset
	for _, id := range model.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.CustomDevelopedParts && !technicalAsset.OutOfScope {
			hasCustomDevelopedParts = true
			if impact == model.LowImpact {
				mostRelevantAsset = technicalAsset
				if technicalAsset.HighestConfidentiality() >= model.Confidential ||
					technicalAsset.HighestIntegrity() >= model.Critical ||
					technicalAsset.HighestAvailability() >= model.Critical {
					impact = model.MediumImpact
				}
			}
			if technicalAsset.Confidentiality >= model.Confidential ||
				technicalAsset.Integrity >= model.Critical ||
				technicalAsset.Availability >= model.Critical {
				impact = model.MediumImpact
			}
			// just for referencing the most interesting asset
			if technicalAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
				mostRelevantAsset = technicalAsset
			}
		}
		if technicalAsset.Technology == model.BuildPipeline {
			hasBuildPipeline = true
		}
		if technicalAsset.Technology == model.SourcecodeRepository {
			hasSourcecodeRepo = true
		}
		if technicalAsset.Technology == model.DevOpsClient {
			hasDevOpsClient = true
		}
	}
	hasBuildInfrastructure := hasBuildPipeline && hasSourcecodeRepo && hasDevOpsClient
	if hasCustomDevelopedParts && !hasBuildInfrastructure {
		risks = append(risks, createRisk(mostRelevantAsset, impact))
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact) model.Risk {
	title := "<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
