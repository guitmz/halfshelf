debugEnvPrefix    db "HALFSHELF_DEBUG="
debugEnvPrefixLen = $ - debugEnvPrefix
hexDigits         db "0123456789abcdef"

dbgEnabledMsg       db "halfshelf: debug tracing enabled", 0xa
dbgEnabledMsgLen    = $ - dbgEnabledMsg
dbgDynMsg           db "halfshelf: target type ET_DYN", 0xa
dbgDynMsgLen        = $ - dbgDynMsg
dbgReserveDynMsg    db "halfshelf: reserving SHELF load window", 0xa
dbgReserveDynMsgLen = $ - dbgReserveDynMsg
dbgLoadBiasMsg      db "halfshelf: load bias = "
dbgLoadBiasMsgLen   = $ - dbgLoadBiasMsg
dbgStackMsg         db "halfshelf: synthetic stack base = "
dbgStackMsgLen      = $ - dbgStackMsg
dbgMapMainMsg       db "halfshelf: mapping SHELF PT_LOAD at "
dbgMapMainMsgLen    = $ - dbgMapMainMsg
dbgMemfdMsg         db "halfshelf: ingesting SHELF payload from stdin via memfd", 0xa
dbgMemfdMsgLen      = $ - dbgMemfdMsg
dbgRelocMsg         db "halfshelf: applying direct entry relocations", 0xa
dbgRelocMsgLen      = $ - dbgRelocMsg
dbgTlsMsg           db "halfshelf: preparing PT_TLS runtime state", 0xa
dbgTlsMsgLen        = $ - dbgTlsMsg
dbgStackBuildMsg    db "halfshelf: rebuilding argc/argv/envp/auxv", 0xa
dbgStackBuildMsgLen = $ - dbgStackBuildMsg
dbgJumpMainMsg      db "halfshelf: jumping to SHELF entry = "
dbgJumpMainMsgLen   = $ - dbgJumpMainMsg

dbgJumpInterpMsg    db "halfshelf: PT_INTERP path is not part of this variant"
dbgJumpInterpMsgLen = $ - dbgJumpInterpMsg

versionMsg    db "halfshelf: SHELF focused userland exec loader v0.0.1 by TMZ (c) 2026", 0xa
versionMsgLen = $ - versionMsg
usageMsg      db "Usage: halfshelf <path-to-shelf-elf>", 0xa
usageMsgLen   = $ - usageMsg

invalidElfMsg        db "halfshelf: target does not look like a valid ELF64 file", 0xa
invalidElfMsgLen     = $ - invalidElfMsg
invalidLayoutMsg     db "halfshelf: ELF header layout is not one this loader understands", 0xa
invalidLayoutMsgLen  = $ - invalidLayoutMsg
invalidSegmentMsg    db "halfshelf: a PT_LOAD file range points outside the staged ELF", 0xa
invalidSegmentMsgLen = $ - invalidSegmentMsg
invalidArchMsg       db "halfshelf: target is not ELF64", 0xa
invalidArchMsgLen    = $ - invalidArchMsg

unsupportedTypeMsg    db "halfshelf: this loader only accepts ET_DYN SHELF payloads", 0xa
unsupportedTypeMsgLen = $ - unsupportedTypeMsg
unsupportedInterpMsg  db "halfshelf: PT_INTERP means this is not a direct entry SHELF image", 0xa
unsupportedInterpMsgLen = $ - unsupportedInterpMsg
unsupportedRelocMsg   db "halfshelf: relocation set is larger than this teaching loader handles", 0xa
unsupportedRelocMsgLen = $ - unsupportedRelocMsg
invalidShelfMsg       db "halfshelf: target is ELF, but not in the narrow SHELF shape we expect", 0xa
invalidShelfMsgLen    = $ - invalidShelfMsg
invalidMetaMsg        db "halfshelf: side metadata is missing fields or disagrees with the payload", 0xa
invalidMetaMsgLen     = $ - invalidMetaMsg

stackStorageTooSmallMsg    db "halfshelf: copied argv/env strings do not fit in the synthetic stack arena", 0xa
stackStorageTooSmallMsgLen = $ - stackStorageTooSmallMsg
openFailedMsg              db "halfshelf: could not open the SHELF input", 0xa
openFailedMsgLen           = $ - openFailedMsg
fstatFailedMsg             db "halfshelf: could not stat the SHELF input", 0xa
fstatFailedMsgLen          = $ - fstatFailedMsg
headerReadFailedMsg        db "halfshelf: could not read the ELF header", 0xa
headerReadFailedMsgLen     = $ - headerReadFailedMsg
fileTooLargeMsg            db "halfshelf: input is larger than the fixed staging buffer", 0xa
fileTooLargeMsgLen         = $ - fileTooLargeMsg
fileReadFailedMsg          db "halfshelf: could not stage the SHELF payload into memory", 0xa
fileReadFailedMsgLen       = $ - fileReadFailedMsg
metaReadFailedMsg          db "halfshelf: could not read the detached SHELF metadata blob", 0xa
metaReadFailedMsgLen       = $ - metaReadFailedMsg
closeFailedMsg             db "halfshelf: finished loading, but close(2) on the input file failed", 0xa
closeFailedMsgLen          = $ - closeFailedMsg
mmapFailedMsg              db "halfshelf: mmap(2) failed while laying out the SHELF image", 0xa
mmapFailedMsgLen           = $ - mmapFailedMsg
phdrReadFailedMsg          db "halfshelf: could not read a program header from disk", 0xa
phdrReadFailedMsgLen       = $ - phdrReadFailedMsg
mprotectFailedMsg          db "halfshelf: mprotect(2) rejected the final segment permissions", 0xa
mprotectFailedMsgLen       = $ - mprotectFailedMsg
archPrctlFailedMsg         db "halfshelf: arch_prctl(2) failed while installing PT_TLS state", 0xa
archPrctlFailedMsgLen      = $ - archPrctlFailedMsg
