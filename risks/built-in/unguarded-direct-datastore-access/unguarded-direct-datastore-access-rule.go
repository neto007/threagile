package unguarded_direct_datastore_access

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "unguarded-direct-datastore-access",
		Title:       "Unguarded Direct Datastore Access",
		Description: "Os armazenamentos de dados acessados através dos limites de confiança devem ser protegidos por algum serviço ou aplicativo de proteção.",
		Impact:      "Se esse risco não for mitigado, os invasores podem atacar diretamente os armazenamentos de dados confidenciais sem nenhum componente de proteção intermediário.",
		ASVS:        "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:      "Encapsulamento de Datastore",
		Mitigation:  "Encapsule o acesso ao armazenamento de dados por trás de um serviço ou aplicativo de proteção.",
		Check:       "As recomendações da folha de dicas vinculada e do capítulo ASVS referenciado são aplicadas?",
		Function:    model.Architecture,
		STRIDE:      model.ElevationOfPrivilege,
		DetectionLogic: "Ativos técnicos no escopo do tipo " + model.Datastore.String() + " (exceto " + model.IdentityStoreLDAP.String() + " quando acessado de " + model.IdentityProvider.String() + " e " + model.FileServer.String() + " quando acessado por meio de protocolos de transferência de arquivos) com classificação de confidencialidade " +
			"de " + model.Confidential.String() + " (ou superior) ou com classificação de integridade de " + model.Critical.String() + " (ou superior) " +
			"que têm fluxos de dados de entrada de ativos externos através de um limite de confiança da rede. O acesso à configuração e implementação do DevOps está excluído desse risco.", // TODO new rule "missing bastion host"?
		RiskAssessment: "Os recursos técnicos correspondentes estão em " + model.LowSeverity.String() + " risco. Quando o " +
			"classificação de confidencialidade é " + model.StrictlyConfidential.String() + " ou a classificação de integridade " +
			"é " + model.MissionCritical.String() + ", a classificação de risco é considerada " + model.MediumSeverity.String() + ". " +
			"Para ativos com valores de RAA superiores a 40%, a classificação de risco aumenta.",
		FalsePositives:             "Quando o chamador é considerado totalmente confiável, como se fosse parte do próprio armazenamento de dados.",
		ModelFailurePossibleReason: false,
		CWE:                        501,
	}
}

func SupportedTags() []string {
	return []string{}
}

// check for datastores that should not be accessed directly across trust boundaries
func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Type == model.Datastore {
			for _, incomingAccess := range model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
				sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId]
				if (technicalAsset.Technology == model.IdentityStoreLDAP || technicalAsset.Technology == model.IdentityStoreDatabase) &&
					sourceAsset.Technology == model.IdentityProvider {
					continue
				}
				if technicalAsset.Confidentiality >= model.Confidential || technicalAsset.Integrity >= model.Critical {
					if incomingAccess.IsAcrossTrustBoundaryNetworkOnly() && !FileServerAccessViaFTP(technicalAsset, incomingAccess) &&
						incomingAccess.Usage != model.DevOps && !model.IsSharingSameParentTrustBoundary(technicalAsset, sourceAsset) {
						highRisk := technicalAsset.Confidentiality == model.StrictlyConfidential ||
							technicalAsset.Integrity == model.MissionCritical
						risks = append(risks, createRisk(technicalAsset, incomingAccess,
							model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId], highRisk))
					}
				}
			}
		}
	}
	return risks
}

func FileServerAccessViaFTP(technicalAsset model.TechnicalAsset, incomingAccess model.CommunicationLink) bool {
	return technicalAsset.Technology == model.FileServer &&
		(incomingAccess.Protocol == model.FTP || incomingAccess.Protocol == model.FTPS || incomingAccess.Protocol == model.SFTP)
}

func createRisk(dataStore model.TechnicalAsset, dataFlow model.CommunicationLink, clientOutsideTrustBoundary model.TechnicalAsset, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky || dataStore.RAA > 40 {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood: model.Likely,
		ExploitationImpact:     impact,
		Title: "<b>Unguarded Direct Datastore Access</b> of <b>" + dataStore.Title + "</b> by <b>" +
			clientOutsideTrustBoundary.Title + "</b> via <b>" + dataFlow.Title + "</b>",
		MostRelevantTechnicalAssetId:    dataStore.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{dataStore.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataFlow.Id + "@" + clientOutsideTrustBoundary.Id + "@" + dataStore.Id
	return risk
}
