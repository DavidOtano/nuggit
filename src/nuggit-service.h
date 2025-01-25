#ifndef NG_NUGGIT_SERVICE_H
#define NG_NUGGIT_SERVICE_H

namespace ng {

struct ng_service {
    virtual bool process() = 0;
};

}  // namespace ng

#endif
