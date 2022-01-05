package unguarded_access_from_internet

import (
	"sort"

	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unguarded-access-from-internet",
		Title: "Unguarded Access From Internet",
		Description: "Ativos expostos à Internet devem ser protegidos por um serviço de proteção, aplicativo, " +
			"ou proxy reverso.",
		Impact: "Se este risco não for mitigado, os invasores podem ser capazes de atacar diretamente sistemas sensíveis sem nenhum componente de proteção entre " +
			"por estarem diretamente expostos na internet.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Encapsulation of Technical Asset",
		Mitigation: "Encapsule o ativo por trás de um serviço de proteção, aplicativo ou proxy reverso. " +
			"Para manutenção do administrador, um host bastion deve ser usado como servidor de salto. " +
			"Para a transferência de arquivos, um host de armazenamento e encaminhamento deve ser usado como uma plataforma de troca indireta de arquivos.",
		Check:    "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function: model.Architecture,
		STRIDE:   model.ElevationOfPrivilege,
		DetectionLogic: "Ativos técnicos dentro do escopo (excluding " + model.LoadBalancer.String() + ") com classificação de confidencialidade " +
			"de " + model.Confidential.String() + " (ou superior) ou com classificação de integridade de " + model.Critical.String() + " (ou superior) quando " +
			"acessado diretamente da internet. Tudo " +
			model.WebServer.String() + ", " + model.WebApplication.String() + ", " + model.ReverseProxy.String() + ", " + model.WAF.String() + ", e " + model.Gateway.String() + " ativos são isentos deste risco quando " +
			"eles não consistem em código desenvolvido de forma personalizada e " +
			"o fluxo de dados consiste apenas em protocolos HTTP ou FTP. Acesso de " + model.Monitoring.String() + " sistemas " +
			"assim como as conexões protegidas por VPN são isentas.",
		RiskAssessment: "Os recursos técnicos correspondentes estão em " + model.LowSeverity.String() + " risco. Quando o " +
			"classificação de confidencialidade é " + model.StrictlyConfidential.String() + " ou a classificação de integridade " +
			"é " + model.MissionCritical.String() + ", a classificação de risco é considerada " + model.MediumSeverity.String() + ". " +
			"Para ativos com valores de RAA superiores a 40%, a classificação de risco aumenta.",
		FalsePositives:             "Quando outros meios de filtrar solicitações do cliente são aplicados equivalentes " + model.ReverseProxy.String() + ", " + model.WAF.String() + ", ou " + model.Gateway.String() + " componentes.",
		ModelFailurePossibleReason: false,
		CWE:                        501,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope {
			commLinks := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			sort.Sort(model.ByTechnicalCommunicationLinkIdSort(commLinks))
			for _, incomingAccess := range commLinks {
				if technicalAsset.Technology != model.LoadBalancer {
					if !technicalAsset.CustomDevelopedParts {
						if (technicalAsset.Technology == model.WebServer || technicalAsset.Technology == model.WebApplication || technicalAsset.Technology == model.ReverseProxy || technicalAsset.Technology == model.WAF || technicalAsset.Technology == model.Gateway) &&
							(incomingAccess.Protocol == model.HTTP || incomingAccess.Protocol == model.HTTPS) {
							continue
						}
						if technicalAsset.Technology == model.Gateway &&
							(incomingAccess.Protocol == model.FTP || incomingAccess.Protocol == model.FTPS || incomingAccess.Protocol == model.SFTP) {
							continue
						}
					}
					if model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Technology == model.Monitoring ||
						incomingAccess.VPN {
						continue
					}
					if technicalAsset.Confidentiality >= model.Confidential || technicalAsset.Integrity >= model.Critical {
						sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId]
						if sourceAsset.Internet {
							highRisk := technicalAsset.Confidentiality == model.StrictlyConfidential ||
								technicalAsset.Integrity == model.MissionCritical
							risks = append(risks, createRisk(technicalAsset, incomingAccess,
								model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId], highRisk))
						}
					}
				}
			}
		}
	}
	return risks
}

func createRisk(dataStore model.TechnicalAsset, dataFlow model.CommunicationLink,
	clientFromInternet model.TechnicalAsset, moreRisky bool) model.Risk {
	impact := model.LowImpact
	if moreRisky || dataStore.RAA > 40 {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:               Category(),
		Severity:               model.CalculateSeverity(model.VeryLikely, impact),
		ExploitationLikelihood: model.VeryLikely,
		ExploitationImpact:     impact,
		Title: "<b>Unguarded Access from Internet</b> of <b>" + dataStore.Title + "</b> by <b>" +
			clientFromInternet.Title + "</b>" + " via <b>" + dataFlow.Title + "</b>",
		MostRelevantTechnicalAssetId:    dataStore.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{dataStore.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataStore.Id + "@" + clientFromInternet.Id + "@" + dataFlow.Id
	return risk
}
