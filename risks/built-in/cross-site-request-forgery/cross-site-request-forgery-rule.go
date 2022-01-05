package cross_site_request_forgery

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "cross-site-request-forgery",
		Title:       "Cross-Site Request Forgery (CSRF)",
		Description: "Quando um aplicativo da web é acessado por meio de protocolos da web, podem surgir riscos de falsificação de solicitação de site cruzado (CSRF).",
		Impact: "Se esse risco permanecer inalterado, os invasores podem enganar os usuários vítimas conectados a ações indesejadas dentro do aplicativo da web " +
			"visitando um site controlado pelo invasor.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
		Action:     "CSRF Prevention",
		Mitigation: "Tente usar tokens anti-CSRF dos padrões de envio duplo (pelo menos para solicitações conectadas). " +
			"Quando o seu esquema de autenticação depende de cookies (como cookies de sessão ou token), considere marcá-los com " +
			"o same-site flag. " +
			"Quando um produto de terceiros é usado em vez de um software desenvolvido sob medida, verifique se o produto aplica a atenuação adequada e garanta um nível de patch razoável.",
		Check:          "As recomendações da folha de dicas vinculada e do capítulo ASVS referenciado são aplicadas?",
		Function:       model.Development,
		STRIDE:         model.Spoofing,
		DetectionLogic: "Aplicativos da web dentro do escopo acessados por meio de protocolos de acesso à web típicos.",
		RiskAssessment: "A classificação de risco depende da classificação de integridade dos dados enviados pelo link de comunicação.",
		FalsePositives: "Os aplicativos da Web que passam pelo estado de autenticação por meio de cabeçalhos personalizados em vez de cookies podem " +
			"eventualmente, ser falsos positivos. Também quando o aplicativo da web " +
			"não é acessado por meio de um componente semelhante ao navegador (ou seja, não por um usuário humano iniciando a solicitação que " +
			"passa por todos os componentes até atingir o aplicativo da web), isso pode ser considerado um falso positivo.",
		ModelFailurePossibleReason: false,
		CWE:                        352,
	}
}

func SupportedTags() []string {
	return []string{}
}

func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || !technicalAsset.Technology.IsWebApplication() {
			continue
		}
		incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if incomingFlow.Protocol.IsPotentialWebAccessProtocol() {
				likelihood := model.VeryLikely
				if incomingFlow.Usage == model.DevOps {
					likelihood = model.Likely
				}
				risks = append(risks, createRisk(technicalAsset, incomingFlow, likelihood))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink, likelihood model.RiskExploitationLikelihood) model.Risk {
	sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>" + technicalAsset.Title + "</b> via <b>" + incomingFlow.Title + "</b> from <b>" + sourceAsset.Title + "</b>"
	impact := model.LowImpact
	if incomingFlow.HighestIntegrity() == model.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
