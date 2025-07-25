// bidirectional_slice.sc
// Author: kaixuanli
// Date: 2025-07-25 14:34:21
/*
  Joern 双向切片脚本（增强版）：
  - 输入：TARGET_FILE、TARGET_LINE 环境变量
  - 以指定文件+行号为起点，做静态调用切片
  - 输出格式：DIRECTION:function|file
*/

val targetFile = sys.env.getOrElse("TARGET_FILE", "")
val targetLine = sys.env.getOrElse("TARGET_LINE", "0").toInt

println(s"DEBUG: 查找目标文件: $targetFile, 行号: $targetLine")

// 调试：列出所有文件
val allFiles = cpg.file.name.l
println(s"DEBUG: CPG中的所有文件 (${allFiles.size} 个):")
allFiles.take(10).foreach(f => println(s"  - $f"))
if (allFiles.size > 10) println(s"  ... 还有 ${allFiles.size - 10} 个文件")

// 更灵活的文件匹配
val matchingFiles = cpg.file.name.l.filter(f => f.contains(targetFile) || targetFile.contains(f.split("/").last))
println(s"DEBUG: 匹配的文件: ${matchingFiles.mkString(", ")}")

// 尝试多种方式定位文件
val targetFileNode = if (matchingFiles.nonEmpty) {
  cpg.file.name(matchingFiles.head)
} else {
  // 尝试精确匹配
  val exactMatch = cpg.file.name(targetFile)
  if (exactMatch.nonEmpty) exactMatch else cpg.file.name(s".*$targetFile.*")
}

println(s"DEBUG: 选中的文件节点数量: ${targetFileNode.size}")

// 定位起点函数
val startMethod = targetFileNode.method.lineNumber(targetLine).headOption
val globalMethod = targetFileNode.method.name("<global>").headOption
val allMethods = targetFileNode.method.l

println(s"DEBUG: 目标文件中的所有方法 (${allMethods.size} 个):")
allMethods.take(5).foreach { m =>
  val lineRange = s"${m.lineNumber.getOrElse("?")} - ${m.lineNumberEnd.getOrElse("?")}"
  println(s"  - ${m.name} (行: $lineRange)")
}

val entryMethod = startMethod.orElse(globalMethod)

println(s"DEBUG: 起点方法: ${entryMethod.map(_.name).getOrElse("未找到")}")

// 收集调用关系
def collectCalls(m: io.shiftleft.codepropertygraph.generated.nodes.Method, visited: Set[String] = Set()): Set[(String, String)] = {
  if (m == null || visited.contains(m.fullName)) return Set()
  val file = m.file.name.headOption.getOrElse("")
  val self = Set((m.name, file))
  val callees = m.call.callee.toList
  self ++ callees.flatMap(c => collectCalls(c, visited + m.fullName))
}

// 执行切片
entryMethod match {
  case Some(method) =>
    println(s"START:${method.name}|${method.file.name.headOption.getOrElse("")}")
    
    // 前向切片（调用关系）
    val slice = collectCalls(method)
    slice.foreach { case (func, file) =>
      println(s"FORWARD:$func|$file")
    }
    
    // 简单的sources和sinks识别
    val sourceNames = List("_REQUEST", "_GET", "_POST", "_COOKIE")
    val sinkNames = List("echo", "print", "eval", "system")
    
    // 查找包含sources的地方
    sourceNames.foreach { src =>
      cpg.identifier.name(s".*$src.*").foreach { id =>
        val method = id.method.name.headOption.getOrElse("<global>")
        val file = id.file.name.headOption.getOrElse("")
        println(s"SOURCE:$method|$file")
      }
    }
    
    // 查找包含sinks的地方
    sinkNames.foreach { sink =>
      cpg.call.name(s".*$sink.*").foreach { call =>
        val method = call.method.name.headOption.getOrElse("<global>")
        val file = call.file.name.headOption.getOrElse("")
        println(s"SINK:$method|$file")
      }
    }
    
  case None =>
    println("ERROR: 无法定位起点函数")
    println(s"DEBUG: 尝试查找包含行号 $targetLine 的任何方法...")
    val anyMethodAtLine = cpg.method.lineNumber(targetLine).l
    println(s"DEBUG: 在行号 $targetLine 找到 ${anyMethodAtLine.size} 个方法:")
    anyMethodAtLine.foreach { m =>
      println(s"  - ${m.name} in ${m.file.name.headOption.getOrElse("unknown")}")
    }
} 