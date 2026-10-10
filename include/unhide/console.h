#pragma once
#include <string>
#include <unhide/models.h>

namespace unhide {
namespace console_saida {

void titulo(const std::string &texto);
void etapa(const std::string &texto);
void progresso(const std::string &texto);
void ok(const std::string &texto);
void alerta(const std::string &texto);
void erro(const std::string &texto);
void linha();
void exibirResumo(const modelos::ResultadoAnalise &r);
void exibirAchados(const modelos::ResultadoAnalise &r);
void exibirVeredito(const modelos::ResultadoAnalise &r);

}
}
