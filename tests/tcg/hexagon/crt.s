    .text
    .globl init
init:
    {
        allocframe(r29,#0):raw
    }
    {
        r0=#256
    }
    {
        evb=r0
    }
    {
        dealloc_return
    }

    .space 240

EventVector:
    { rte }
    { rte }
    { rte }
    { rte }
    { rte }
    { rte }
    { rte }
    { rte }
    { rte }
    { rte }

    .globl pass
pass:
    { r0=#24 }
    { 
        r1 = #0
        r3 = #3735924747
    }
    { trap0(#0) }

    .globl fail
fail:
    { r0=#24 }
    {
        r1 = #1
        r3 = #3735924747
    }
    { trap0(#0) }
