package unencrypted_communication

import (
	"github.com/threagile/threagile/model"
)

func Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "unencrypted-communication",
		Title: "Unencrypted Communication",
		Description: "Devido à classificação de confidencialidade e / ou integridade dos ativos de dados transferidos pelo " +
			"communication link this connection must be encrypted.",
		Impact:     "Se este risco for ignorado, os invasores de rede podem ser capazes de espancar os dados sensíveis não criptografados entre os componentes.",
		ASVS:       "V9 - Communication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
		Action:     "Encryption of Communication Links",
		Mitigation: "Aplique criptografia de camada de transporte para o link de comunicação.",
		Check:      "As recomendações do cheat sheet e do ASVS/CSVS referenciado são aplicadas?",
		Function:   model.Operations,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "Ligações de comunicação técnica não criptografadas de ativos técnicos de escopo (excluindoexcluindo " + model.Monitoring.String() + " tráfego, bem como" + model.LocalFileAccess.String() + " e " + model.InProcessLibraryCall.String() + ") " +
			"transferindo dados confidenciais.iais.iais.", // TODO more detailed text required here
		RiskAssessment: "Dependendo da classificação de confidencialidade dos ativos de dados transferidos ou de alto risco.",
		FalsePositives: "Quando todos os dados sensíveis enviados pelo link de comunicação já estiver totalmente criptografado no documento ou no nível de dados. " +
			"Além disso, a comunicação intra-contêiner / pod pode ser considerada falsa positiva quando a plataforma de orquestração de contêineres lida com criptografia.neres lida com criptografia.",
		ModelFailurePossibleReason: false,
		CWE:                        319,
	}
}

func SupportedTags() []string {
	return []string{}
}

// check for communication links that should be encrypted due to their confidentiality and/or integrity
func GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			transferringAuthData := dataFlow.Authentication != model.NoneAuthentication
			sourceAsset := model.ParsedModelRoot.TechnicalAssets[dataFlow.SourceId]
			targetAsset := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
			if !technicalAsset.OutOfScope || !sourceAsset.OutOfScope {
				if !dataFlow.Protocol.IsEncrypted() && !dataFlow.Protocol.IsProcessLocal() &&
					!sourceAsset.Technology.IsUnprotectedCommsTolerated() &&
					!targetAsset.Technology.IsUnprotectedCommsTolerated() {
					addedOne := false
					for _, sentDataAsset := range dataFlow.DataAssetsSent {
						dataAsset := model.ParsedModelRoot.DataAssets[sentDataAsset]
						if isHighSensitivity(dataAsset) || transferringAuthData {
							risks = append(risks, createRisk(technicalAsset, dataFlow, true, transferringAuthData))
							addedOne = true
							break
						} else if !dataFlow.VPN && isMediumSensitivity(dataAsset) {
							risks = append(risks, createRisk(technicalAsset, dataFlow, false, transferringAuthData))
							addedOne = true
							break
						}
					}
					if !addedOne {
						for _, receivedDataAsset := range dataFlow.DataAssetsReceived {
							dataAsset := model.ParsedModelRoot.DataAssets[receivedDataAsset]
							if isHighSensitivity(dataAsset) || transferringAuthData {
								risks = append(risks, createRisk(technicalAsset, dataFlow, true, transferringAuthData))
								break
							} else if !dataFlow.VPN && isMediumSensitivity(dataAsset) {
								risks = append(risks, createRisk(technicalAsset, dataFlow, false, transferringAuthData))
								break
							}
						}
					}
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, dataFlow model.CommunicationLink, highRisk bool, transferringAuthData bool) model.Risk {
	impact := model.MediumImpact
	if highRisk {
		impact = model.HighImpact
	}
	target := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
	title := "<b>Comunicação não criptografada</b> nomeada <b>" + dataFlow.Title + "</b> entreb >" + technicalAsset.Title + "</b> e <b>" + target.Title + "</b>"
	if transferringAuthData {
		title += " transferindo dados de autenticação (like credentials, token, session-id, etc.)"
	}
	if dataFlow.VPN {
		title += " (Mesmo as conexões protegidas por VPN precisam criptografar seus dados em trânsito quando a confidencialidade é " +
			"avaliada " + model.StrictlyConfidential.String() + " ou a integridade é avaliada " + model.MissionCritical.String() + ")"
	}
	likelihood := model.Unlikely
	if dataFlow.IsAcrossTrustBoundaryNetworkOnly() {
		likelihood = model.Likely
	}
	risk := model.Risk{
		Category:                        Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataFlow.Id + "@" + technicalAsset.Id + "@" + target.Id
	return risk
}

func isHighSensitivity(dataAsset model.DataAsset) bool {
	return dataAsset.Confidentiality == model.StrictlyConfidential || dataAsset.Integrity == model.MissionCritical
}

func isMediumSensitivity(dataAsset model.DataAsset) bool {
	return dataAsset.Confidentiality == model.Confidential || dataAsset.Integrity == model.Critical
}
