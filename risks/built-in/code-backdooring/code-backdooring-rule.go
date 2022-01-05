package code_backdooring

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "code-backdooring",
		Title: "Code Backdooring",
		Description: "Para cada componente do pipeline de compilaçao, podem surgir riscos de backdooring onde os invasores comprometem o pipeline de compilcão " +
			"para permitir que artefatos de backdooring sejam enviados para a produção Além do codigo direto, isso incluir " +
			"backdooring de dependencias e até de mesmo  de infraestrutura de compilação baixo nivel.",
		Impact: "Se este risco permanecer inalterado, os invasores podem ser capazes de executar o código e assumir o controle completamente " +
			"ambientes de produção.",
		ASVS:       "V10 - Malicious Code Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
		Action:     "Build Pipeline Hardening",
		Mitigation: "Reduza a superfície de ataque de backdoor do pipeline de construção, não expondo diretamente o pipeline de construção " +
			"componentes na Internet pública e também não os expõe na frente de clientes de desenvolvedor não gerenciados (fora do escopo)." +
			"Considere também o uso de assinatura de código para evitar modificações no código.",
		Check:    "As recomendações do cheat sheet e do capítulo ASVS referenciado são aplicadas?",
		Function: model.Operations,
		STRIDE:   model.Tampering,
		DetectionLogic: "Ativos técnicos relevantes de desenvolvimento dentro do escopo que são acessados por fora do escopo não gerenciado " +
			"clientes desenvolvedores e / ou são acessados diretamente por qualquer tipo de componente localizado na Internet (não VPN) ou eles próprios estão localizados diretamente " +
			"na internet.",
		RiskAssessment: "A classificação de risco depende da classificação de confidencialidade e integridade do código que está sendo manuseado e implantado " +
			"bem como a colocação/chamada deste ativo técnico na / da internet.", // TODO also take the CIA rating of the deployment targets (and their data) into account?
		FalsePositives: "Quando o build-pipeline e o sourcecode-repo não são expostos à Internet e considerados totalmente " +
			"confiável (o que implica que todos os clientes que acessam também são considerados totalmente confiáveis em termos de gerenciamento de patches " +
			"e proteção aplicada, que deve ser equivalente a um ambiente de cliente desenvolvedor gerenciado), isso pode ser considerado um falso positivo " +
			"após revisão individual.",
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
		if !technicalAsset.OutOfScope && technicalAsset.Technology.IsDevelopmentRelevant() {
			if technicalAsset.Internet {
				risks = append(risks, createRisk(technicalAsset, true))
				continue
			}

			// TODO: ensure that even internet or unmanaged clients coming over a reverse-proxy or load-balancer like component are treated as if it was directly accessed/exposed on the internet or towards unmanaged dev clients

			//riskByLinkAdded := false
			for _, callerLink := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				caller := model.ParsedModelRoot.TechnicalAssets[callerLink.SourceId]
				if (!callerLink.VPN && caller.Internet) || caller.OutOfScope {
					risks = append(risks, createRisk(technicalAsset, true))
					//riskByLinkAdded = true
					break
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, elevatedRisk bool) model.Risk {
	title := "<b>Code Backdooring</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := model.LowImpact
	if technicalAsset.Technology != model.CodeInspectionPlatform {
		if elevatedRisk {
			impact = model.MediumImpact
		}
		if technicalAsset.HighestConfidentiality() >= model.Confidential || technicalAsset.HighestIntegrity() >= model.Critical {
			impact = model.MediumImpact
			if elevatedRisk {
				impact = model.HighImpact
			}
		}
	}
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
		DataBreachProbability:        model.Probable,
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
