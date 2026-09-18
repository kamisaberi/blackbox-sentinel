#include "core/orchestrator.hpp"
#include <iostream>

// Include headers for all 26 decoupled modules
#ifdef SENTINEL_ENABLE_01_SIEM
#include "../modules/01_siem_core/siem_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_02_UEBA
#include "../modules/02_ueba/ueba_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_03_NDR
#include "../modules/03_ndr/ndr_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_04_IDS_IPS
#include "../modules/04_ids_ips/ids_ips_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_05_WAF
#include "../modules/05_waf/waf_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_06_EDR
#include "../modules/06_edr/edr_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_07_EPP_NGAV
#include "../modules/07_epp_ngav/epp_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_08_NAC
#include "../modules/08_nac/nac_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_09_CWPP
#include "../modules/09_cwpp/cwpp_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_10_BAD
#include "../modules/10_bad/bad_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_11_RASP
#include "../modules/11_rasp/rasp_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_12_ITDR
#include "../modules/12_itdr/itdr_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_13_DDOS
#include "../modules/13_ddos/ddos_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_14_ATO
#include "../modules/14_ato/ato_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_15_NGFW
#include "../modules/15_ngfw/ngfw_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_16_CDR
#include "../modules/16_cdr/cdr_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_17_IOT_SEC
#include "../modules/17_iot_sec/iot_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_18_CPS_SEC
#include "../modules/18_cps_sec/cps_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_19_SWG
#include "../modules/19_swg/swg_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_20_FSE
#include "../modules/20_fse/fse_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_21_SIDE_CHANNEL
#include "../modules/21_side_channel/side_channel_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_22_DFIR
#include "../modules/22_dfir/dfir_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_23_AI_TRISM
#include "../modules/23_ai_trism/ai_trism_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_24_ZTNA
#include "../modules/24_ztna/ztna_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_25_FDP
#include "../modules/25_fdp/fdp_module.hpp"
#endif
#ifdef SENTINEL_ENABLE_26_DDP
#include "../modules/26_ddp/ddp_module.hpp"
#endif

namespace sentinel::core {

Orchestrator::Orchestrator() = default;

Orchestrator::~Orchestrator() {
    shutdown_all_modules();
}

bool Orchestrator::bootstrap_all_modules(const std::string& config_dir) {
    std::lock_guard<std::mutex> lock(orchestrator_mutex_);
    if (is_running_) return true;

    std::cout << "[Orchestrator] Bootstrapping active security modules..." << std::endl;

    // Helper lambda to initialize and register modules
    auto load_mod = [&](std::shared_ptr<ISentinelModule> mod) {
        if (!mod) return;
        ConfigManager::instance().load_module_config(mod->get_id(), config_dir);
        std::string cfg = ConfigManager::instance().get_module_config(mod->get_id());
        
        if (mod->initialize(cfg)) {
            mod->start();
            EventBus::instance().subscribe(mod);
            modules_.push_back(mod);
        } else {
            std::cerr << "[Orchestrator Warning] Module " << mod->get_name() << " failed to initialize." << std::endl;
        }
    };

    // Instantiate enabled modules
#ifdef SENTINEL_ENABLE_01_SIEM
    load_mod(std::make_shared<modules::siem::SiemModule>());
#endif
#ifdef SENTINEL_ENABLE_02_UEBA
    load_mod(std::make_shared<modules::ueba::UebaModule>());
#endif
#ifdef SENTINEL_ENABLE_03_NDR
    load_mod(std::make_shared<modules::ndr::NdrModule>());
#endif
#ifdef SENTINEL_ENABLE_04_IDS_IPS
    load_mod(std::make_shared<modules::ids_ips::IdsIpsModule>());
#endif
#ifdef SENTINEL_ENABLE_05_WAF
    load_mod(std::make_shared<modules::waf::WafModule>());
#endif
#ifdef SENTINEL_ENABLE_06_EDR
    load_mod(std::make_shared<modules::edr::EdrModule>());
#endif
#ifdef SENTINEL_ENABLE_07_EPP_NGAV
    load_mod(std::make_shared<modules::epp_ngav::EppModule>());
#endif
#ifdef SENTINEL_ENABLE_08_NAC
    load_mod(std::make_shared<modules::nac::NacModule>());
#endif
#ifdef SENTINEL_ENABLE_09_CWPP
    load_mod(std::make_shared<modules::cwpp::CwppModule>());
#endif
#ifdef SENTINEL_ENABLE_10_BAD
    load_mod(std::make_shared<modules::bad::BadModule>());
#endif
#ifdef SENTINEL_ENABLE_11_RASP
    load_mod(std::make_shared<modules::rasp::RaspModule>());
#endif
#ifdef SENTINEL_ENABLE_12_ITDR
    load_mod(std::make_shared<modules::itdr::ItdrModule>());
#endif
#ifdef SENTINEL_ENABLE_13_DDOS
    load_mod(std::make_shared<modules::ddos::DdosModule>());
#endif
#ifdef SENTINEL_ENABLE_14_ATO
    load_mod(std::make_shared<modules::ato::AtoModule>());
#endif
#ifdef SENTINEL_ENABLE_15_NGFW
    load_mod(std::make_shared<modules::ngfw::NgfwModule>());
#endif
#ifdef SENTINEL_ENABLE_16_CDR
    load_mod(std::make_shared<modules::cdr::CdrModule>());
#endif
#ifdef SENTINEL_ENABLE_17_IOT_SEC
    load_mod(std::make_shared<modules::iot_sec::IotModule>());
#endif
#ifdef SENTINEL_ENABLE_18_CPS_SEC
    load_mod(std::make_shared<modules::cps_sec::CpsModule>());
#endif
#ifdef SENTINEL_ENABLE_19_SWG
    load_mod(std::make_shared<modules::swg::SwgModule>());
#endif
#ifdef SENTINEL_ENABLE_20_FSE
    load_mod(std::make_shared<modules::fse::FseModule>());
#endif
#ifdef SENTINEL_ENABLE_21_SIDE_CHANNEL
    load_mod(std::make_shared<modules::side_channel::SideChannelModule>());
#endif
#ifdef SENTINEL_ENABLE_22_DFIR
    load_mod(std::make_shared<modules::dfir::DfirModule>());
#endif
#ifdef SENTINEL_ENABLE_23_AI_TRISM
    load_mod(std::make_shared<modules::ai_trism::AiTrismModule>());
#endif
#ifdef SENTINEL_ENABLE_24_ZTNA
    load_mod(std::make_shared<modules::ztna::ZtnaModule>());
#endif
#ifdef SENTINEL_ENABLE_25_FDP
    load_mod(std::make_shared<modules::fdp::FdpModule>());
#endif
#ifdef SENTINEL_ENABLE_26_DDP
    load_mod(std::make_shared<modules::ddp::DdpModule>());
#endif

    is_running_ = true;
    std::cout << "[Orchestrator] Successfully operational with " << modules_.size() << " active security modules." << std::endl;
    return true;
}

void Orchestrator::shutdown_all_modules() {
    std::lock_guard<std::mutex> lock(orchestrator_mutex_);
    if (!is_running_) return;

    std::cout << "[Orchestrator] Shutting down all active modules..." << std::endl;
    for (auto& mod : modules_) {
        if (mod) {
            mod->stop();
        }
    }
    EventBus::instance().clear();
    modules_.clear();
    is_running_ = false;
}

size_t Orchestrator::active_module_count() const {
    std::lock_guard<std::mutex> lock(orchestrator_mutex_);
    return modules_.size();
}

} // namespace sentinel::core