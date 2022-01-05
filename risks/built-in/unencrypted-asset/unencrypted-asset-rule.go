package unencrypted_asset

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unencrypted-asset",
		Title: "Unencrypted Technical Assets",
		Description: "Devido à classificação de confidencialidade do próprio ativo técnico e / ou os ativos de dados processados " +
			"Este ativo técnico deve ser criptografado.A classificação de risco depende do próprio ativo técnico da sensibilidade e dos ativos de dados armazenados.",
		Impact:     "Se este risco for ignorado, os invasores poderão acessar dados não criptografados quando comprometer com êxito componentes sensíveis.",
		ASVS:       "V6 - Stored Cryptography Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
		Action:     "Encryption of Technical Asset",
		Mitigation: "Aplique criptografia ao ativo técnico.",
		Check:      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:   model.Operations,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "Ativos técnicos não criptografados no escopo (excluindo " + model.ReverseProxy.String() +
			", " + model.LoadBalancer.String() + ", " + model.WAF.String() + ", " + model.IDS.String() +
			", " + model.IPS.String() + "e componentes incorporados como " + model.Library.String() + ") " +
			"armazenar ativos de dados classificados pelo menos como " + model.Confidential.String() + " ou " + model.Critical.String() + ". " +
			"Para ativos técnicos que armazenam ativos de dados classificados como " + model.StrictlyConfidential.String() + " ou " + model.MissionCritical.String() + " a " +
			"criptografia deve ser do tipo " + model.DataWithEnduserIndividualKey.String() + ".",
		RiskAssessment:             "Dependendo da classificação de confidencialidade dos ativos de dados armazenados ou de alto risco.",
		FalsePositives:             "Quando todos os dados confidenciais armazenados dentro do ativo já estiver totalmente criptografado no documento ou no nível de dados.",
		ModelFailurePossibleReason: false,
		CWE:                        311,
	}
}

func SupportedTags() []string {
	return []string{}
}

// check for technical assets that should be encrypted due to their confidentiality
func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && !IsEncryptionWaiver(technicalAsset) &&
			(technicalAsset.HighestConfidentiality() >= model.Confidential ||
				technicalAsset.HighestIntegrity() >= model.Critical) {
			verySensitive := technicalAsset.HighestConfidentiality() == model.StrictlyConfidential ||
				technicalAsset.HighestIntegrity() == model.MissionCritical
			requiresEnduserKey := verySensitive && technicalAsset.Technology.IsUsuallyStoringEnduserData()
			if technicalAsset.Encryption == model.NoneEncryption {
				impact := model.MediumImpact
				if verySensitive {
					impact = model.HighImpact
				}
				risks = append(risks, createRisk(technicalAsset, impact, requiresEnduserKey))
			} else if requiresEnduserKey &&
				(technicalAsset.Encryption == model.Transparent || technicalAsset.Encryption == model.DataWithSymmetricSharedKey || technicalAsset.Encryption == model.DataWithAsymmetricSharedKey) {
				risks = append(risks, createRisk(technicalAsset, model.MediumImpact, requiresEnduserKey))
			}
		}
	}
	return risks
}

// Simple routing assets like 'Reverse Proxy' or 'Load Balancer' usually don't have their own storage and thus have no
// encryption requirement for the asset itself (though for the communication, but that's a different rule)
func IsEncryptionWaiver(asset model.TechnicalAsset) bool {
	return asset.Technology == model.ReverseProxy || asset.Technology == model.LoadBalancer ||
		asset.Technology == model.WAF || asset.Technology == model.IDS || asset.Technology == model.IPS ||
		asset.Technology.IsEmbeddedComponent()
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, requiresEnduserKey bool) model.Risk {
	title := "<b>Unencrypted Technical Asset</b> named <b>" + technicalAsset.Title + "</b>"
	if requiresEnduserKey {
		title += " missing enduser-individual encryption with " + model.DataWithEnduserIndividualKey.String()
	}
	risk := model.Risk{
		Category:                     Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
