#pragma once
#include "review_registry.hpp"

namespace enhanced {
using namespace usb;
enum class ActionKind { File, Process, Startup, Policy, Service, Task, Recheck };
enum class ActionStatus { Pending, Done, Failed, Kept };
struct ActionResult {
    ActionKind kind=ActionKind::File;
    ActionStatus status=ActionStatus::Pending;
    S target, reason;
    bool blocksRecovery=false;
};
struct Treatment {
    std::vector<ActionResult> actions;
    std::vector<Finding> isolated;
    void add(ActionKind kind,ActionStatus status,const S& target,const S& reason=L"",bool blocks=false) {
        actions.push_back({kind,status,target,reason,blocks});
    }
    bool blocked() const {for(const auto& a:actions)if(a.blocksRecovery && a.status!=ActionStatus::Done)return true;return false;}
    size_t count(ActionKind kind,ActionStatus status) const {size_t n=0;for(const auto& a:actions)if(a.kind==kind && a.status==status)++n;return n;}
};
inline bool requiresDecision(const Finding& f) {
    return !f.confirmed && (f.review==ReviewKind::HighRiskName || f.review==ReviewKind::ResidualName ||
        f.review==ReviewKind::LinkVariant || f.review==ReviewKind::KnownHash);
}
inline S findingKey(const Finding& f) {return lower(full(f.path))+L"|"+lower(f.digest)+L"|"+num(f.fileSize)+L"|"+num(f.created.dwHighDateTime)+L":"+num(f.created.dwLowDateTime);}
struct RecoveryContext {
    bool scanned=false, criticalComplete=false;
    S root; DWORD serial=0;
    std::vector<Finding> outstanding;
    std::set<S> retained;
    Treatment treatment;
    std::vector<S> unreviewedSettings;
};
inline const S& usbScanRequiredText() {
    static const S text=L"请您选择 U 盘后重新扫描杀毒，再恢复文件。";
    return text;
}
inline bool matchesRecoveryVolume(const RecoveryContext& c,const S& root,DWORD serial) {
    // Computer-only scans deliberately have no volume path. Never normalize that empty path.
    return c.scanned && !c.root.empty() && !root.empty() && same(c.root,root) && c.serial==serial;
}
inline void requireContext(const RecoveryContext& c,const S& root,DWORD serial) {
    NativeFs native;
    if(!matchesRecoveryVolume(c,root,serial))throw Error{usbScanRequiredText()};
    if(!c.criticalComplete)throw Error{L"关键位置尚未检查完，请先继续检查。"};
    if(!c.unreviewedSettings.empty())throw Error{L"还有启动项或磁盘显示设置未确认。请在处理列表选择处理或保留；保留不会删除设置。"};
    for(const auto& a:c.treatment.actions)if(a.blocksRecovery && a.status!=ActionStatus::Done)
        throw Error{L"请先解决："+a.target+L"\r\n"+a.reason};
    for(const auto& f:c.outstanding) {
        if(f.confirmed || f.review==ReviewKind::KnownHash)throw Error{L"请先隔离已知病毒文件："+f.path};
        if(requiresDecision(f)) {
            if(!c.retained.count(findingKey(f)))throw Error{L"还有待确认文件，请先查看处理结果："+f.path};
            noLinks(f.path);WIN32_FILE_ATTRIBUTE_DATA info{};
            if(f.digest.empty() || size(f.path)!=f.fileSize || size(f.path)>64ULL*1024*1024 || hash(f.path)!=f.digest ||
                !GetFileAttributesExW(xp(f.path).c_str(),GetFileExInfoStandard,&info) || CompareFileTime(&f.created,&info.ftCreationTime)!=0)
                throw Error{L"之前选择保留的文件已变化，请重新检查："+f.path};
        }
    }
}
} // namespace enhanced
