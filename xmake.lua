---@format disable
---@diagnostic disable

set_xmakever('2.9.7')

set_project('nuggit')

rule('base')
    on_load(function(target)
        target:set('languages', 'c++20')
        target:set('targetdir', './build')
        target:set('warnings', 'all', 'pedantic', 'error')
        target:add('includedirs', './include')
        target:add('cxxflags', '-Wno-unused-function')
        if is_plat('windows') then
            target:add('defines', '_CRT_SECURE_NO_WARNINGS')
            --target:add('cxxflags', '-target x86_64-pc-windows-gnu', { force = true })
        end

        if is_mode('release') then
            target:set('symbols', 'hidden')
            target:set('optimize', 'fastest')
            target:set('strip', 'all')
        elseif is_mode('debug') then
            target:set('symbols', 'debug')
            target:set('optimize', 'none')
        end
        if is_plat('windows') then
            target:add('defines', 'WIN32_LEAN_AND_MEAN')
            target:add('syslinks', 'ws2_32')
        end
    end)
rule_end()

option('increment-build-number')
    on_check(function(option)
        local build_number = tonumber(io.readfile('./buildnum.txt'))
        build_number = build_number + 1
        io.writefile('./buildnum.txt', tostring(build_number))
    end)
option_end()

target('semver')
    set_kind('phony')
    add_options('increment-build-number')
    add_configfiles('./include/semver.h.in')
    set_configdir('./include')
    on_config(function(target)
        local build_number = tonumber(io.readfile('./buildnum.txt'))
        target:set('configvar', 'BUILD_MAJOR', 0)
        target:set('configvar', 'BUILD_MINOR', 1)
        target:set('configvar', 'BUILD_NUMBER', build_number)
    end)
target_end()

target('chat-server')
    set_kind('static')
    add_rules('base')
    add_deps('semver')
    add_files("src/chat-server/*.cpp")
    after_build(function(target)
        os.cp('./config.ini', './build/config.ini')
    end)
target_end()

target('crypt')
    set_kind('static')
    add_rules('base')
    add_deps('semver')
    add_files("src/crypt/*.cpp")
target_end()

target('peer')
    set_kind('static')
    add_rules('base')
    add_deps('semver')
    add_files("src/peer/*.cpp")
target_end()

target('nuggit')
    set_kind('binary')
    add_rules('base')
    add_deps('semver', 'chat-server', 'crypt', 'peer')
    add_links('chat-server', 'crypt', 'peer')
    add_files('src/*.cpp')
target_end()
