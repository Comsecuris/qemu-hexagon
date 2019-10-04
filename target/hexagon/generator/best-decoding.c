/*
 * Copyright (c) 2017-2019 Comsecuris UG (haftungsbeschraenkt)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <float.h>

typedef struct {
  uint32_t Value;
  uint32_t Mask;
} Instruction;

void printTimes(char *String, unsigned Times) {
  while (Times --> 0)
    printf("%s", String);
}

void printBinaryBits(uint32_t Value, unsigned Bits) {
  unsigned I = Bits;
  while (I --> 0)
    printf("%c", Value & (1 << I) ? '1' : '0');
}

void printBinary(uint32_t Value) {
  unsigned I = 32;
  while (I --> 0)
    printf("%c", Value & (1 << I) ? '1' : '0');
}

void printWithColors(FILE *File, uint32_t Value, uint8_t Colors[32]) {
  unsigned I = 32;
  while (I --> 0)
    fprintf(File, "\x1B[%dm%c", (int) Colors[I], Value & (1 << I) ? '1' : '0');
  fprintf(File, "\x1B[0m");
}

void printInstruction(Instruction *Inst) {
  unsigned I = 32;
  while (I --> 0)
    printf("%s%c%s", Inst->Mask & (1 << I) ? "\x1B[31m" : "\x1B[0m", Inst->Value & (1 << I) ? '1' : '0', "\x1B[0m");
}

void printWithChoice(uint32_t Value, uint8_t *Choice, unsigned Size) {
  uint32_t ChoiceToInt = 0;
  for (unsigned I = 0; I < Size; I++)
    ChoiceToInt |= 1 << (Choice[I]);
  Instruction Temp = { Value , ChoiceToInt };
  printInstruction(&Temp);
}

int compareInstructions(const void *LHS, const void *RHS) {
  assert(LHS != NULL);
  assert(RHS != NULL);
  return ((Instruction *) RHS)->Value - ((Instruction *) LHS)->Value;
}

uint32_t extractBits(uint32_t Value, uint8_t *Choice, unsigned Size) {
  uint32_t Result = 0;
  for (unsigned I = 0; I < Size; I++)
    Result |= ((Value & (1 << Choice[I]) ? 1 : 0) << I);
  return Result;
}

void quickTest(void) {
  uint8_t Choice[4] = { 0, 1, 2, 3 };
  assert(extractBits(0b10111011, Choice, 4) == 0b1011);
  assert(extractBits(0b10111111, Choice, 4) == 0b1111);

  uint8_t Choice2[4] = { 1, 3, 5 };
  assert(extractBits(0b1101010, Choice2, 3) == 0b111);
  assert(extractBits(0b010101, Choice2, 3) == 0);
}

unsigned findBest(Instruction *Instructions,
                  Instruction *TargetInstructions,
                  Instruction *SelectedInstructions,
                  unsigned InstructionCount,
                  Instruction *MaskedValue,
                  uint8_t *BestChoice,
                  float *Score,
                  unsigned *Count,
                  unsigned Bits) {
  unsigned BestBits = 0;
  float BestScore = FLT_MAX;

  // 1. Select only the instructions of our interest
  unsigned TargetInstructionsCount = 0;
  for (unsigned I = 0; I < InstructionCount; I++) {
    uint32_t Mask = MaskedValue->Mask & Instructions[I].Mask;
    if ((Instructions[I].Value & Mask) == (MaskedValue->Value & Mask))
      TargetInstructions[TargetInstructionsCount++] = Instructions[I];
  }
  *Count = TargetInstructionsCount;

  // 2. Compute the choosable bits
  uint8_t Choosable[32] = { 0 };
  unsigned ChoosableCount = 0;
  for (unsigned I = 0; I < 32; I++)
    if ((MaskedValue->Mask & (1 << I)) == 0)
      Choosable[ChoosableCount++] = I;

  // Initialize combination
  uint8_t Choice[32];
  for (unsigned J = 0; J < Bits; J++)
    Choice[J] = J;

  int K = 1;
  while (K >= 0) {

    // Get the corresponding choosable indexes
    uint8_t RealChoice[32];
    for (unsigned J = 0; J < Bits; J++)
      RealChoice[J] = Choosable[Choice[J]];

    // Keep only the interesting bits
    for (unsigned L = 0; L < TargetInstructionsCount; L++) {
      SelectedInstructions[L].Value = extractBits(TargetInstructions[L].Value,
                                                  RealChoice,
                                                  Bits);
      SelectedInstructions[L].Mask = extractBits(TargetInstructions[L].Mask,
                                                 RealChoice,
                                                 Bits);
    }

    unsigned TotalMatches = 0;
    unsigned Options = (1 << Bits);
    for (unsigned L = 0; L < (1U << Bits); L++) {
      bool NoMatch = true;
      for (unsigned M = 0; M < TargetInstructionsCount; M++) {
        uint32_t MaskedL = L & SelectedInstructions[M].Mask;
        uint32_t Value = SelectedInstructions[M].Value;
        if (MaskedL == Value) {
          TotalMatches++;
          NoMatch = false;
        }
      }

      if (NoMatch)
        Options--;
    }

    float NewScore = (float) TotalMatches / Options;
    if (Options > 0 && NewScore < BestScore) {
      BestScore = NewScore;
      BestBits = Bits;
      memcpy(BestChoice, RealChoice, sizeof(Choice));
    }

    // Get next combination
    for (K = (int) Bits - 1; K >= 0; K--) {
      // Can we increment this?
      if (Choice[K] < ChoosableCount - 1) {
        Choice[K]++;
        if (Choice[K] + Bits - 1 - K <= ChoosableCount - 1) {
          for (K++; K < (int) Bits; K++)
            Choice[K] = Choice[K - 1] + 1;
          break;
        }
      }
    }

  }

  *Score = BestScore;
  return BestBits;
}

void go(Instruction *Instructions,
        Instruction *TargetInstructions,
        Instruction *SelectedInstructions,
        unsigned InstructionCount,
        Instruction *Tmp,
        uint8_t Choices[32][32],
        unsigned Depth,
        uint8_t *BitsPerMemoryAccess,
        unsigned MaxDepth) {
  unsigned BestBits = 0;
  float Score;
  unsigned Count;
  BestBits = findBest(Instructions,
                      TargetInstructions,
                      SelectedInstructions,
                      InstructionCount,
                      Tmp,
                      &Choices[Depth][0],
                      &Score,
                      &Count,
                      BitsPerMemoryAccess[Depth]);

  printTimes("  ", 2 + Depth * 2);
  printf("\"bits\": [%d", Choices[Depth][0]);
  for (unsigned I = 1; I < BitsPerMemoryAccess[Depth]; I++)
    printf(", %d", Choices[Depth][I]);
  printf("]");
  printf(",\n");
  printTimes("  ", 2 + Depth * 2);

  if (Depth < MaxDepth - 1) {
    printf("\"options\": {\n");
    Instruction Tmp2 = *Tmp;
    for (unsigned M = 0; M < BestBits; M++)
      Tmp2.Mask |= 1 << Choices[Depth][M];

    for (unsigned L = 0; L < (1U << BestBits); L++) {
      printTimes("  ", 2 + Depth * 2 + 1);
      printf("\"");
      printBinaryBits(L, BestBits);
      printf("\": {\n");

      Tmp2.Value = Tmp->Value;
      for (unsigned M = 0; M < BestBits; M++)
        if (L & (1 << M))
          Tmp2.Value |= 1 << Choices[Depth][M];
      go(Instructions,
         TargetInstructions,
         SelectedInstructions,
         InstructionCount,
         &Tmp2,
         Choices,
         Depth + 1,
         BitsPerMemoryAccess,
         MaxDepth);

      printTimes("  ", 2 + Depth * 2 + 1);
      printf("}");
      if (L != (1U << BestBits) - 1)
        printf(",");
      printf("\n");
    }

  } else {
    printf("\"instructions\": {\n");
    Instruction Tmp2 = *Tmp;
    for (unsigned M = 0; M < BestBits; M++)
      Tmp2.Mask |= 1 << Choices[Depth][M];

    for (unsigned L = 0; L < (1U << BestBits); L++) {
      printTimes("  ", 2 + Depth * 2 + 1);
      printf("\"");
      printBinaryBits(L, BestBits);
      printf("\": [");

      Tmp2.Value = Tmp->Value;
      for (unsigned M = 0; M < BestBits; M++)
        if (L & (1 << M))
          Tmp2.Value |= 1 << Choices[Depth][M];

      bool IsFirst = true;
      for (unsigned M = 0; M < InstructionCount; M++) {
        uint32_t Mask = Instructions[M].Mask & Tmp2.Mask;
        if ((Tmp2.Value & Mask) == (Instructions[M].Value & Mask)) {
          if (!IsFirst) {
            printf(", ");
          }
          IsFirst = false;
          printf("%d", M);
        }
      }

      printf("]");
      if (L != (1U << BestBits) - 1)
        printf(",");
      printf("\n");
    }

    // Print to stderr coloful stuff
    if (Score != FLT_MAX) {
      uint8_t Colors[32] = { 0 };
      for (unsigned K = 0; K < MaxDepth; K++) {
        for (unsigned L = 0; L < BitsPerMemoryAccess[K]; L++) {
          assert(Colors[Choices[K][L]] == 0);
          if (32 + K < 37)
            Colors[Choices[K][L]] = 32 + K;
        }
      }

      printWithColors(stderr, Tmp->Value, Colors);
      fprintf(stderr, " %2.2f/%d\n", Score, Count);
    }

  }
  printTimes("  ", 2 + Depth * 2);
  printf("}");
  printf("\n");
}

int main(int argc, char *argv[]) {

  if (argc < 3) {
    fprintf(stderr, "Usage: %s INSTRUCTIONS_CSV"
            " BITS_PER_ACCESS1 BITS_PER_ACCESS2...\n", argv[0]);
    return EXIT_FAILURE;
  }

  #define MAX_MEMORY_ACCESSES 32
  unsigned MemoryAccesses = argc - 2;
  assert(MemoryAccesses < MAX_MEMORY_ACCESSES);
  uint8_t BitsPerMemoryAccess[MAX_MEMORY_ACCESSES];
  unsigned TotalBits = 0;
  for (unsigned I = 0; I < MemoryAccesses; I++) {
    unsigned Bits = atoi(argv[2 + I]);
    if (Bits <= 0 || Bits > 32) {
      fprintf(stderr,
              "Invalid number of bits for memory access %d: %u\n",
              I + 1,
              Bits);
      return EXIT_FAILURE;
    }
    TotalBits += Bits;
    BitsPerMemoryAccess[I] = Bits;
  }
  assert(TotalBits < 32);

  quickTest();

  FILE *File = fopen(argv[1], "r");
  if (File == NULL) {
    fprintf(stderr, "Couldn't open the input file: %s\n", argv[1]);
    return EXIT_FAILURE;
  }

  size_t BufferSize = 100;
  size_t InstructionCount = 0;
  Instruction *Buffer = (Instruction *) calloc(1000, sizeof(Instruction));

  unsigned BitsMet = 0;

  bool LastWasSpace = true;
  bool Corrupted = false;
  char LastInput = 0;
  uint32_t Value = 0;
  uint32_t Mask = 0;
  while (true) {
    char Input;
    size_t BytesRead = fread(&Input, 1, 1, File);
    if (BytesRead == 0)
      break;

    assert(BytesRead == 1);

    if (Input == '\n') {
      if (!Corrupted && BitsMet == 32) {
        /* printBinary(Value); */
        /* printf("\n"); */
        /* printBinary(Mask); */
        /* printf("\n\n"); */

        Buffer[InstructionCount].Value = Value;
        Buffer[InstructionCount].Mask = Mask;
        InstructionCount++;

        if (InstructionCount >= BufferSize) {
          BufferSize *= 2;
          Buffer = realloc(Buffer, BufferSize * sizeof(Instruction));
        }

      }

      Value = 0;
      Mask = 0;
      BitsMet = 0;
      LastWasSpace = true;

      Corrupted = false;
      continue;
    }

    if (Corrupted)
      continue;

    if (BitsMet < 32) {
      bool IsSpace = Input == ' ' || Input == ',';
      if (!LastWasSpace && IsSpace) {
        if (LastInput == '0' || LastInput == '1')
          Mask |= 1 << (31 - BitsMet);

        if (LastInput == '1')
          Value |= 1 << (31 - BitsMet);

        BitsMet++;
      } else if (!LastWasSpace && !IsSpace) {
        Corrupted = true;
      }
    }

    LastWasSpace = Input == ' ' || Input == ',';
    LastInput = Input;
 }

  fclose(File);

  // Dump all instructions
  printf("{\n");
  printf("  \"instructions\": [\n");
  for (unsigned I = 0; I < InstructionCount; I++) {
    printf("    [\"");
    printBinary(Buffer[I].Value);
    printf("\", \"");
    printBinary(Buffer[I].Mask);
    printf("\"]");
    if (I != InstructionCount - 1)
      printf(",");
    printf("\n");
  }
  printf("  ],\n");
  printf("  \"decode\": {\n");

  // Call the recursive function to find the best at each level
  Instruction *TargetInstructions = calloc(InstructionCount, sizeof(Instruction));
  Instruction *SelectedInstructions = calloc(InstructionCount, sizeof(Instruction));
  uint8_t Choices[32][32];
  bzero(&Choices, sizeof(Choices));
  Instruction Fixed = { 0, 0 };
  go(Buffer,
     TargetInstructions,
     SelectedInstructions,
     InstructionCount,
     &Fixed,
     Choices,
     0,
     BitsPerMemoryAccess,
     MemoryAccesses);
  printf("  }\n");
  printf("}\n");

  free(Buffer);

  return EXIT_SUCCESS;
}
