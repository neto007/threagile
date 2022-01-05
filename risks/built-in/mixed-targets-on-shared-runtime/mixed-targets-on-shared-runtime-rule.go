package mixed_targets_on_shared_runtime

import (
	"sort"

	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "mixed-targets-on-shared-runtime",
		Title: "Mixed Targets on Shared Runtime",
		Description: "Alvos diferentes de invasores (como componentes de front-end e back-end / armazenamento de dados) não devem ser executados no mesmo " +
			"tempo de execução compartilhado (subjacente).",
		Impact: "Se este risco não for mitigado, os invasores que atacam com sucesso outros componentes do sistema podem ter um caminho fácil para " +
			"alvos mais valiosos, pois estão em execução no mesmo tempo de execução compartilhado.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Runtime Separation",
		Mitigation: "Use ambientes de tempo de execução separados para executar diferentes componentes de destino ou aplique estilos de separação semelhantes para " +
			"evitar problemas relacionados à carga ou violação originados de mais um ativo que enfrenta o invasor e também impacta o " +
			"outros ativos de back-end / armazenamento de dados com classificação mais crítica.",
		Check:    "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function: model.Operations,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "O tempo de execução compartilhado executando ativos técnicos de diferentes limites de confiança está em risco. " +
			"Além disso, misturar back-end / armazenamento de dados com componentes de front-end no mesmo tempo de execução compartilhado é considerado um risco.",
		RiskAssessment: "A classificação de risco (baixo ou médio) depende da classificação de confidencialidade, integridade e disponibilidade de " +
			"o ativo técnico em execução no tempo de execução compartilhado.",
		FalsePositives: "Quando todos os ativos em execução no tempo de execução compartilhado são reforçados e protegidos da mesma forma como se todos fossem " +
			"contendo/processando dados altamente confidenciais.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	// as in Go ranging over map is random order, range over them in sorted (hence reproducible) way:
	keys := make([]string, 0)
	for k, _ := range model.ParsedModelRoot.SharedRuntimes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		sharedRuntime := model.ParsedModelRoot.SharedRuntimes[key]
		currentTrustBoundaryId := ""
		hasFrontend, hasBackend := false, false
		riskAdded := false
		for _, technicalAssetId := range sharedRuntime.TechnicalAssetsRunning {
			technicalAsset := model.ParsedModelRoot.TechnicalAssets[technicalAssetId]
			if len(currentTrustBoundaryId) > 0 && currentTrustBoundaryId != technicalAsset.GetTrustBoundaryId() {
				risks = append(risks, createRisk(sharedRuntime))
				riskAdded = true
				break
			}
			currentTrustBoundaryId = technicalAsset.GetTrustBoundaryId()
			if technicalAsset.Technology.IsExclusivelyFrontendRelated() {
				hasFrontend = true
			}
			if technicalAsset.Technology.IsExclusivelyBackendRelated() {
				hasBackend = true
			}
		}
		if !riskAdded && hasFrontend && hasBackend {
			risks = append(risks, createRisk(sharedRuntime))
		}
	}
	return risks
}

func createRisk(sharedRuntime model.SharedRuntime) model.Risk {
	impact := model.LowImpact
	if isMoreRisky(sharedRuntime) {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood: model.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Mixed Targets on Shared Runtime</b> named <b>" + sharedRuntime.Title + "</b> might enable attackers moving from one less " +
			"valuable target to a more valuable one", // TODO list at least the assets in the text which are running on the shared HW
		MostRelevantSharedRuntimeId: sharedRuntime.Id,
		DataBreachProbability:       model.Improbable,
		DataBreachTechnicalAssetIDs: sharedRuntime.TechnicalAssetsRunning,
	}
	risk.SyntheticId = risk.Category.Id + "@" + sharedRuntime.Id
	return risk
}

func isMoreRisky(sharedRuntime model.SharedRuntime) bool {
	for _, techAssetId := range sharedRuntime.TechnicalAssetsRunning {
		techAsset := model.ParsedModelRoot.TechnicalAssets[techAssetId]
		if techAsset.Confidentiality == model.StrictlyConfidential || techAsset.Integrity == model.MissionCritical ||
			techAsset.Availability == model.MissionCritical {
			return true
		}
	}
	return false
}
