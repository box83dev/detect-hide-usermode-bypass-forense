#pragma once
#include <string>
#include <vector>
#include <functional>
#include <unhide/models.h>

namespace unhide {
namespace arquivos {

std::vector<modelos::ArquivoOculto> varrer(const std::vector<std::string> &caminhos, bool completo, std::function<void(const std::string&)> progresso);
std::vector<std::string> caminhosPadrao(bool completo);

}
}
