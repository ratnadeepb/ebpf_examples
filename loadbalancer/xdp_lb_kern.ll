; ModuleID = 'xdp_lb_kern.c'
source_filename = "xdp_lb_kern.c"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf"

%struct.xdp_md = type { i32, i32, i32, i32, i32 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }

@xdp_load_balancer.____fmt = internal constant [14 x i8] c"got something\00", align 1
@xdp_load_balancer.____fmt.1 = internal constant [25 x i8] c"got a tcp packet from %x\00", align 1
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1
@llvm.used = appending global [2 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_load_balancer to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @xdp_load_balancer(%struct.xdp_md* nocapture readonly %0) #0 section "xdp_lb" {
  %2 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0
  %3 = load i32, i32* %2, align 4, !tbaa !2
  %4 = zext i32 %3 to i64
  %5 = inttoptr i64 %4 to i8*
  %6 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1
  %7 = load i32, i32* %6, align 4, !tbaa !7
  %8 = zext i32 %7 to i64
  %9 = inttoptr i64 %8 to i8*
  %10 = tail call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* getelementptr inbounds ([14 x i8], [14 x i8]* @xdp_load_balancer.____fmt, i64 0, i64 0), i32 14) #1
  %11 = inttoptr i64 %4 to %struct.ethhdr*
  %12 = getelementptr i8, i8* %5, i64 14
  %13 = icmp ugt i8* %12, %9
  br i1 %13, label %67, label %14

14:                                               ; preds = %1
  %15 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %11, i64 0, i32 2
  %16 = load i16, i16* %15, align 1, !tbaa !8
  %17 = icmp eq i16 %16, 8
  br i1 %17, label %18, label %67

18:                                               ; preds = %14
  %19 = getelementptr i8, i8* %5, i64 23
  %20 = load i8, i8* %19, align 1, !tbaa !11
  %21 = icmp eq i8 %20, 6
  br i1 %21, label %22, label %67

22:                                               ; preds = %18
  %23 = getelementptr i8, i8* %5, i64 26
  %24 = bitcast i8* %23 to i32*
  %25 = load i32, i32* %24, align 4, !tbaa !13
  %26 = tail call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* getelementptr inbounds ([25 x i8], [25 x i8]* @xdp_load_balancer.____fmt.1, i64 0, i64 0), i32 25, i32 %25) #1
  %27 = load i32, i32* %24, align 4, !tbaa !13
  %28 = icmp eq i32 %27, 67113388
  br i1 %28, label %29, label %37

29:                                               ; preds = %22
  %30 = tail call i64 inttoptr (i64 5 to i64 ()*)() #1
  %31 = and i64 %30, 1
  %32 = icmp eq i64 %31, 0
  %33 = select i1 %32, i8 2, i8 3
  %34 = zext i8 %33 to i32
  %35 = shl nuw nsw i32 %34, 24
  %36 = or i32 %35, 4524
  br label %37

37:                                               ; preds = %22, %29
  %38 = phi i32 [ %36, %29 ], [ 67113388, %22 ]
  %39 = phi i8 [ %33, %29 ], [ 4, %22 ]
  %40 = getelementptr i8, i8* %5, i64 30
  %41 = bitcast i8* %40 to i32*
  store i32 %38, i32* %41, align 4, !tbaa !14
  %42 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %11, i64 0, i32 0, i64 5
  store i8 %39, i8* %42, align 1
  store i32 83890604, i32* %24, align 4, !tbaa !13
  %43 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %11, i64 0, i32 1, i64 5
  store i8 5, i8* %43, align 1, !tbaa !15
  %44 = getelementptr i8, i8* %5, i64 24
  %45 = bitcast i8* %44 to i16*
  store i16 0, i16* %45, align 2, !tbaa !16
  %46 = bitcast i8* %12 to i32*
  %47 = tail call i64 inttoptr (i64 28 to i64 (i32*, i32, i32*, i32, i32)*)(i32* null, i32 0, i32* %46, i32 20, i32 0) #1
  %48 = lshr i64 %47, 16
  %49 = icmp eq i64 %48, 0
  %50 = and i64 %47, 65535
  %51 = add nuw nsw i64 %50, %48
  %52 = select i1 %49, i64 %47, i64 %51
  %53 = lshr i64 %52, 16
  %54 = icmp eq i64 %53, 0
  %55 = and i64 %52, 65535
  %56 = add nuw nsw i64 %55, %53
  %57 = select i1 %54, i64 %52, i64 %56
  %58 = lshr i64 %57, 16
  %59 = icmp eq i64 %58, 0
  %60 = and i64 %57, 65535
  %61 = add nuw nsw i64 %60, %58
  %62 = select i1 %59, i64 %57, i64 %61
  %63 = lshr i64 %62, 16
  %64 = add i64 %63, %62
  %65 = trunc i64 %64 to i16
  %66 = xor i16 %65, -1
  store i16 %66, i16* %45, align 2, !tbaa !16
  br label %67

67:                                               ; preds = %37, %18, %14, %1
  %68 = phi i32 [ 0, %1 ], [ 2, %14 ], [ 3, %37 ], [ 2, %18 ]
  ret i32 %68
}

attributes #0 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.0-4ubuntu1 "}
!2 = !{!3, !4, i64 0}
!3 = !{!"xdp_md", !4, i64 0, !4, i64 4, !4, i64 8, !4, i64 12, !4, i64 16}
!4 = !{!"int", !5, i64 0}
!5 = !{!"omnipotent char", !6, i64 0}
!6 = !{!"Simple C/C++ TBAA"}
!7 = !{!3, !4, i64 4}
!8 = !{!9, !10, i64 12}
!9 = !{!"ethhdr", !5, i64 0, !5, i64 6, !10, i64 12}
!10 = !{!"short", !5, i64 0}
!11 = !{!12, !5, i64 9}
!12 = !{!"iphdr", !5, i64 0, !5, i64 0, !5, i64 1, !10, i64 2, !10, i64 4, !10, i64 6, !5, i64 8, !5, i64 9, !10, i64 10, !4, i64 12, !4, i64 16}
!13 = !{!12, !4, i64 12}
!14 = !{!12, !4, i64 16}
!15 = !{!5, !5, i64 0}
!16 = !{!12, !10, i64 10}
