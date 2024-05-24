import vertexai
from vertexai.generative_models import GenerativeModel, Part


class GeminiAgent:
    def __init__(self):
        self.project_id = "applied-theme-424308-e6"
        self.region = "us-central1"
        self.model_name = "gemini-1.5-pro-preview-0514"
        self.system_instruction = """
You are an expert in analyzing assembly instructions and source code. Your task is to determine if the patch is present in the assembly instructions of a function. This task involves three key steps:
1. Understand the changes introduced by the patch.
2. Identify the segment of the provided assembly instructions that corresponds to the changed part of the source code based on the given inputs.
3. Determine whether the located segment contains the patch by analyzing the changes brought by the patch and the identified assembly instruction segment.
4. Note: When analyzing the assembly instructions, do not simply check if the logic introduced by the patch is present. The same logic might have existed before the patch was applied. After introducing new logic, there should be an additional set of instructions compared to the original. 

Requirements:
1. You MUST read the inputs carefully and use Chain of Thought reasoning to determine the answer. Mimic answering in the background five times and provide the most frequently appearing answer. 
2. Furthermore, please strictly adhere to the output format specified below, do not answer the analysis progress, and do not provide any additional information.:
    **Output Format**:
    - contain patch: 'Yes' or 'No'
    - corresponding assembly instruction segment: (Example format: jg <LOC> cmp eax,0x301 jge <LOC> cmp eax,0x201 je <LOC> cmp eax,0x202 je <LOC> jmp <LOC> lea rsi,<MEM> lea rcx,<MEM> lea rdx,<MEM>)
    - key reason: (give the key reason for your judgment)"""

        # Initialize Vertex AI
        # pip3 install --upgrade --user google-cloud-aiplatform
        # gcloud auth application-default login
        vertexai.init(project=self.project_id, location=self.region)
        # Load the model
        self.multimodal_model = GenerativeModel(model_name=self.model_name, system_instruction=self.system_instruction)

    def generate_content(self, message_text):
        # Query the model
        generation_config = {
            "temperature": 0.3,
        }
        response = self.multimodal_model.generate_content(contents=message_text, generation_config=generation_config)
        return response

    def patch_presence_detect(self, function_source_codes, patches, assembly_instructions):
        message_text = f"""
**Inputs**:
- Source Code Before Patch: "{function_source_codes}"
- Patches(json): {patches}
- Assembly Instructions: "{assembly_instructions}"
"""
        response = self.generate_content(message_text)
        return response.text


if __name__ == '__main__':
    message_text = """
**Inputs**:
- Source Code Before Patch: "av_cold int ff_mpv_common_init(MpegEncContext *s) { int i; int nb_slices = (HAVE_THREADS && s->avctx->active_thread_type & FF_THREAD_SLICE) ? s->avctx->thread_count : 1; if (s->encoding && s->avctx->slices) nb_slices = s->avctx->slices; if (s->codec_id == AV_CODEC_ID_MPEG2VIDEO && !s->progressive_sequence) s->mb_height = (s->height + 31) / 32 * 2; else s->mb_height = (s->height + 15) / 16; if (s->avctx->pix_fmt == AV_PIX_FMT_NONE) { av_log(s->avctx, AV_LOG_ERROR, "STR"); return -1; } if (nb_slices > MAX_THREADS || (nb_slices > s->mb_height && s->mb_height)) { int max_slices; if (s->mb_height) max_slices = FFMIN(MAX_THREADS, s->mb_height); else max_slices = MAX_THREADS; av_log(s->avctx, AV_LOG_WARNING, "STR" "STR", nb_slices, max_slices); nb_slices = max_slices; } if ((s->width || s->height) && av_image_check_size(s->width, s->height, 0, s->avctx)) return -1; dct_init(s); avcodec_get_chroma_sub_sample(s->avctx->pix_fmt, &s->chroma_x_shift, &s->chroma_y_shift); FF_ALLOCZ_OR_GOTO(s->avctx, s->picture, MAX_PICTURE_COUNT * sizeof(Picture), fail); for (i = 0; i < MAX_PICTURE_COUNT; i++) { s->picture[i].f = av_frame_alloc(); if (!s->picture[i].f) goto fail; } memset(&s->next_picture, 0, sizeof(s->next_picture)); memset(&s->last_picture, 0, sizeof(s->last_picture)); memset(&s->current_picture, 0, sizeof(s->current_picture)); memset(&s->new_picture, 0, sizeof(s->new_picture)); s->next_picture.f = av_frame_alloc(); if (!s->next_picture.f) goto fail; s->last_picture.f = av_frame_alloc(); if (!s->last_picture.f) goto fail; s->current_picture.f = av_frame_alloc(); if (!s->current_picture.f) goto fail; s->new_picture.f = av_frame_alloc(); if (!s->new_picture.f) goto fail; if (init_context_frame(s)) goto fail; s->parse_context.state = -1; s->context_initialized = 1; memset(s->thread_context, 0, sizeof(s->thread_context)); s->thread_context[0] = s; if (nb_slices > 1) { for (i = 0; i < nb_slices; i++) { if (i) { s->thread_context[i] = av_memdup(s, sizeof(MpegEncContext)); if (!s->thread_context[i]) goto fail; } if (init_duplicate_context(s->thread_context[i]) < 0) goto fail; s->thread_context[i]->start_mb_y = (s->mb_height * (i) + nb_slices / 2) / nb_slices; s->thread_context[i]->end_mb_y = (s->mb_height * (i + 1) + nb_slices / 2) / nb_slices; } } else { if (init_duplicate_context(s) < 0) goto fail; s->start_mb_y = 0; s->end_mb_y = s->mb_height; } s->slice_context_count = nb_slices; return 0; fail: ff_mpv_common_end(s); return -1; }"
- Patches(json): [{'vul_snippet_codes': 's->avctx->active_thread_type & FF_THREAD_SLICE) ? s->avctx->thread_count : 1; if (s->encoding && s->avctx->slices) nb_slices = s->avctx->slices;', 'fixed_snippet_codes': 's->avctx->active_thread_type & FF_THREAD_SLICE) ? s->avctx->thread_count : 1; + clear_context(s); + if (s->encoding && s->avctx->slices) nb_slices = s->avctx->slices;'}, {'vul_snippet_codes': 'if (!s->picture[i].f) goto fail; } - memset(&s->next_picture, 0, sizeof(s->next_picture)); - memset(&s->last_picture, 0, sizeof(s->last_picture)); - memset(&s->current_picture, 0, sizeof(s->current_picture)); - memset(&s->new_picture, 0, sizeof(s->new_picture)); s->next_picture.f = av_frame_alloc(); if (!s->next_picture.f) goto fail;', 'fixed_snippet_codes': 'if (!s->picture[i].f) goto fail; } s->next_picture.f = av_frame_alloc(); if (!s->next_picture.f) goto fail;'}]
- Assembly Instructions: "endbr64 push rbp mov rbp,rsp push rbx sub rsp,0x28 mov <MEM>,rdi mov rax,<MEM> mov rax,<MEM> mov eax,<MEM> and eax,0x2 test eax,eax je <LOC> mov rax,<MEM> mov rax,<MEM> mov eax,<MEM> jmp <LOC> mov eax,0x1 mov <MEM>,eax mov rax,<MEM> mov eax,<MEM> test eax,eax je <LOC> mov rax,<MEM> mov rax,<MEM> mov eax,<MEM> test eax,eax je <LOC> mov rax,<MEM> mov rax,<MEM> mov eax,<MEM> mov <MEM>,eax mov rax,<MEM> mov eax,<MEM> cmp eax,0x2 jne <LOC> mov rax,<MEM> mov eax,<MEM> test eax,eax jne <LOC> mov rax,<MEM> mov eax,<MEM> add eax,0x1f lea edx,<MEM> test eax,eax cmovs eax,edx sar eax,0x5 lea edx,<MEM> mov rax,<MEM> mov <MEM>,edx jmp <LOC> mov rax,<MEM> mov eax,<MEM> add eax,0xf lea edx,<MEM> test eax,eax cmovs eax,edx sar eax,0x4 mov edx,eax mov rax,<MEM> mov <MEM>,edx mov rax,<MEM> mov rax,<MEM> mov eax,<MEM> cmp eax,0xffffffff jne <LOC> mov rax,<MEM> mov rax,<MEM> lea rdx,<MEM> mov esi,0x10 mov rdi,rax mov eax,0x0 call <av_log> mov eax,0xffffffff jmp <LOC> cmp <MEM>,0x20 jg <LOC> mov rax,<MEM> mov eax,<MEM> cmp <MEM>,eax jle <LOC> mov rax,<MEM> mov eax,<MEM> test eax,eax je <LOC> mov rax,<MEM> mov eax,<MEM> test eax,eax je <LOC> mov rax,<MEM> mov eax,<MEM> mov edx,0x20 cmp eax,0x20 cmovg eax,edx mov <MEM>,eax jmp <LOC> mov <MEM>,0x20 mov rax,<MEM> mov rax,<MEM> mov ecx,<MEM> mov edx,<MEM> mov r8d,ecx mov ecx,edx lea rdx,<MEM> mov esi,0x18 mov rdi,rax mov eax,0x0 call <av_log> mov eax,<MEM> mov <MEM>,eax mov rax,<MEM> mov eax,<MEM> test eax,eax jne <LOC> mov rax,<MEM> mov eax,<MEM> test eax,eax je <LOC> mov rax,<MEM> mov rax,<MEM> mov rdx,<MEM> mov edx,<MEM> mov esi,edx mov rdx,<MEM> mov edx,<MEM> mov edi,edx mov rcx,rax mov edx,0x0 call <av_image_check_size> test eax,eax je <LOC> mov eax,0xffffffff jmp <LOC> mov rax,<MEM> mov rdi,rax call <dct_init> mov rax,<MEM> lea rdx,<MEM> mov rax,<MEM> lea rcx,<MEM> mov rax,<MEM> mov rax,<MEM> mov eax,<MEM> mov rsi,rcx mov edi,eax call <avcodec_get_chroma_sub_sample> mov edi,0x2d00 call <av_mallocz> mov rdx,rax mov rax,<MEM> mov <MEM>,rdx mov rax,<MEM> mov rax,<MEM> test rax,rax jne <LOC> mov rax,<MEM> mov rax,<MEM> lea rdx,<MEM> mov esi,0x10 mov rdi,rax mov eax,0x0 call <av_log> jmp <LOC> mov <MEM>,0x0 jmp <LOC> mov rax,<MEM> mov rcx,<MEM> mov eax,<MEM> movsxd rdx,eax mov rax,rdx shl rax,0x2 add rax,rdx shl rax,0x6 lea rbx,<MEM> call <av_frame_alloc> mov <MEM>,rax mov rax,<MEM> mov rcx,<MEM> mov eax,<MEM> movsxd rdx,eax mov rax,rdx shl rax,0x2 add rax,rdx shl rax,0x6 add rax,rcx mov rax,<MEM> test rax,rax je <LOC> add <MEM>,0x1 cmp <MEM>,0x23 jle <LOC> mov rax,<MEM> add rax,0x5a8 mov edx,0x140 mov esi,0x0 mov rdi,rax call <memset@plt> mov rax,<MEM> add rax,0x468 mov edx,0x140 mov esi,0x0 mov rdi,rax call <memset@plt> mov rax,<MEM> add rax,0x828 mov edx,0x140 mov esi,0x0 mov rdi,rax call <memset@plt> mov rax,<MEM> add rax,0x6e8 mov edx,0x140 mov esi,0x0 mov rdi,rax call <memset@plt> call <av_frame_alloc> mov rdx,<MEM> mov <MEM>,rax mov rax,<MEM> mov rax,<MEM> test rax,rax je <LOC> call <av_frame_alloc> mov rdx,<MEM> mov <MEM>,rax mov rax,<MEM> mov rax,<MEM> test rax,rax je <LOC> call <av_frame_alloc> mov rdx,<MEM> mov <MEM>,rax mov rax,<MEM> mov rax,<MEM> test rax,rax je <LOC> call <av_frame_alloc> mov rdx,<MEM> mov <MEM>,rax mov rax,<MEM> mov rax,<MEM> test rax,rax je <LOC> mov rax,<MEM> mov rdi,rax call <init_context_frame> test eax,eax jne <LOC> mov rax,<MEM> mov <MEM>,0xffffffff mov rax,<MEM> mov <MEM>,0x1 mov rax,<MEM> add rax,0x360 mov edx,0x100 mov esi,0x0 mov rdi,rax call <memset@plt> mov rax,<MEM> mov rdx,<MEM> mov <MEM>,rdx cmp <MEM>,0x1 jle <LOC> mov <MEM>,0x0 jmp <LOC> cmp <MEM>,0x0 je <LOC> mov rax,<MEM> mov esi,0x2918 mov rdi,rax call <av_memdup> mov rdx,<MEM> mov ecx,<MEM> movsxd rcx,ecx add rcx,0x6c mov <MEM>,rax mov rax,<MEM> mov edx,<MEM> movsxd rdx,edx add rdx,0x6c mov rax,<MEM> test rax,rax je <LOC> mov rax,<MEM> mov edx,<MEM> movsxd rdx,edx add rdx,0x6c mov rax,<MEM> mov rdi,rax call <init_duplicate_context> test eax,eax js 7c1d16 <ff_mpv_common_init+OFFSET> mov rax,<MEM> mov eax,<MEM> imul eax,<MEM> mov edx,eax mov eax,<MEM> mov ecx,eax shr ecx,0x1f add eax,ecx sar eax,1 add edx,eax mov rax,<MEM> mov ecx,<MEM> movsxd rcx,ecx add rcx,0x6c mov rcx,<MEM> mov eax,edx cdq idiv <MEM> mov <MEM>,eax mov rax,<MEM> mov eax,<MEM> mov edx,<MEM> add edx,0x1 imul edx,eax mov eax,<MEM> mov ecx,eax shr ecx,0x1f add eax,ecx sar eax,1 add edx,eax mov rax,<MEM> mov ecx,<MEM> movsxd rcx,ecx add rcx,0x6c mov rcx,<MEM> mov eax,edx cdq idiv <MEM> mov <MEM>,eax add <MEM>,0x1 mov eax,<MEM> cmp eax,<MEM> jl <LOC> jmp <LOC> mov rax,<MEM> mov rdi,rax call <init_duplicate_context> test eax,eax js 7c1d19 <ff_mpv_common_init+OFFSET> mov rax,<MEM> mov <MEM>,0x0 mov rax,<MEM> mov edx,<MEM> mov rax,<MEM> mov <MEM>,edx mov rax,<MEM> mov edx,<MEM> mov <MEM>,edx mov eax,0x0 jmp <LOC> nop jmp <LOC> nop jmp <LOC> nop jmp <LOC> nop jmp <LOC> nop jmp <LOC> nop jmp <LOC> nop jmp <LOC> nop jmp <LOC> nop mov rax,<MEM> mov rdi,rax call <ff_mpv_common_end> mov eax,0xffffffff add rsp,0x28 pop rbx pop rbp ret"
"""

    agent = GeminiAgent()
    response = agent.generate_content(message_text)
    print(response.text)
