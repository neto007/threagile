package unnecessary_data_asset

import (
	"sort"

	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unnecessary-data-asset",
		Title: "Unnecessary Data Asset",
		Description: "Quando um ativo de dados não é processado ou armazenado por nenhum ativo de dados e também não transferido por qualquer " +
			"Links de comunicação, este é um indicador para um recurso de dados desnecessário (ou para um modelo incompleto).",
		Impact: "Se este risco for ignorado, os invasores poderão acessar ativos de dados desnecessários usando " +
			"outras vulnerabilidades.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Redução de superfície de ataque",
		Mitigation: "Try to avoid having data assets that are not required/used.",
		Check:      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:   model.Architecture,
		STRIDE:     model.ElevationOfPrivilege,
		DetectionLogic: "Ativos de dados modelados não processados ou armazenados por quaisquer ativos de dados e também não transferidos por qualquer " +
			"Links de comunicação..",
		RiskAssessment:             model.LowSeverity.String(),
		FalsePositives:             "Geralmente não falsos positivos, pois isso parece um modelo incompleto.leto.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	// first create them in memory - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	unusedDataAssetIDs := make(map[string]bool)
	for k := range model.ParsedModelRoot.DataAssets {
		unusedDataAssetIDs[k] = true
	}
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		for _, processedDataAssetID := range technicalAsset.DataAssetsProcessed {
			delete(unusedDataAssetIDs, processedDataAssetID)
		}
		for _, storedDataAssetID := range technicalAsset.DataAssetsStored {
			delete(unusedDataAssetIDs, storedDataAssetID)
		}
		for _, commLink := range technicalAsset.CommunicationLinks {
			for _, sentDataAssetID := range commLink.DataAssetsSent {
				delete(unusedDataAssetIDs, sentDataAssetID)
			}
			for _, receivedDataAssetID := range commLink.DataAssetsReceived {
				delete(unusedDataAssetIDs, receivedDataAssetID)
			}
		}
	}
	var keys []string
	for k := range unusedDataAssetIDs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, unusedDataAssetID := range keys {
		risks = append(risks, createRisk(unusedDataAssetID))
	}
	return risks
}

func createRisk(unusedDataAssetID string) model.Risk {
	unusedDataAsset := model.ParsedModelRoot.DataAssets[unusedDataAssetID]
	title := "<b>Ativos de dados desnecessários</b> nomeada <b>" + unusedDataAsset.Title + "</b>"
	risk := model.Risk{
		Category:                    Category(),
		Severity:                    model.CalculateSeverity(model.Unlikely, model.LowImpact),
		ExploitationLikelihood:      model.Unlikely,
		ExploitationImpact:          model.LowImpact,
		Title:                       title,
		MostRelevantDataAssetId:     unusedDataAsset.Id,
		DataBreachProbability:       model.Improbable,
		DataBreachTechnicalAssetIDs: []string{unusedDataAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + unusedDataAsset.Id
	return risk
}
