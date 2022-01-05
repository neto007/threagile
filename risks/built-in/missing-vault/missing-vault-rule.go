package missing_vault

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "missing-vault",
		Title: "Missing Vault (Secret Storage)",
		Description: "A fim de evitar o risco de vazamento de segredos por meio de arquivos de configuração (quando atacado por vulnerabilidades sendo capaz de " +
			"ler arquivos como Path-Traversal e outros), é uma prática recomendada usar um processo protegido separado com autenticação adequada, " +
			"autorização e registro de auditoria para acessar segredos de configuração (como credenciais, chaves privadas, certificados de cliente, etc.). " +
			"This component is usually some kind of Vault.",
		Impact: "If this risk is unmitigated, attackers might be able to easier steal config secrets (like credentials, private keys, client certificates, etc.) once " +
			"Este componente é geralmente algum tipo de Vault.",
		ASVS:           "V6 - Stored Cryptography Verification Requirements",
		CheatSheet:     "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
		Action:         "Vault (Secret Storage)",
		Mitigation:     "Considere o uso de um Vault (armazenamento secreto) para armazenar e acessar segredos de configuração com segurança (como credenciais, chaves privadas, certificados de cliente, etc.).",
		Check:          "Existe um Vault (armazenamento secreto)?",
		Function:       model.Architecture,
		STRIDE:         model.InformationDisclosure,
		DetectionLogic: "Modelos sem cofre (armazenamento secreto).",
		RiskAssessment: "A classificação de risco depende da sensibilidade do próprio ativo técnico e dos ativos de dados processados e armazenados.",
		FalsePositives: "Modelos em que nenhum recurso técnico tem qualquer tipo de dados de configuração confidenciais para proteger " +
			"podem ser considerados falsos positivos após revisão individual.",
		ModelFailurePossibleReason: true,
		CWE:                        522,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	hasVault := false
	var mostRelevantAsset model.TechnicalAsset
	impact := model.LowImpact
	for _, id := range model.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if techAsset.Technology == model.Vault {
			hasVault = true
		}
		if techAsset.HighestConfidentiality() >= model.Confidential ||
			techAsset.HighestIntegrity() >= model.Critical ||
			techAsset.HighestAvailability() >= model.Critical {
			impact = model.MediumImpact
		}
		if techAsset.Confidentiality >= model.Confidential ||
			techAsset.Integrity >= model.Critical ||
			techAsset.Availability >= model.Critical {
			impact = model.MediumImpact
		}
		// just for referencing the most interesting asset
		if techAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
			mostRelevantAsset = techAsset
		}
	}
	if !hasVault {
		risks = append(risks, createRisk(mostRelevantAsset, impact))
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact) model.Risk {
	title := "<b>Missing Vault (Secret Storage)</b> in the threat model (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
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
