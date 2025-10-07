'use client'

import React, { useState, useEffect } from 'react'
import { 
  Shield, 
  MessageCircle, 
  Clock,
  CheckCircle,
  AlertTriangle,
  Star,
  Search,
  Eye,
  Reply
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { auth, db } from '@/lib/firebase'
import { collection, onSnapshot, query, orderBy, doc, updateDoc } from 'firebase/firestore'
import { User as FirebaseUser } from 'firebase/auth'
import Image from 'next/image'

interface Question {
  id: string
  content: string
  student: {
    name: string
    email: string
    avatar: string
  }
  category: string
  timestamp: Date
  priority: 'low' | 'medium' | 'high' | 'urgent'
  status: 'unanswered' | 'answered' | 'resolved'
  likes: number
  views: number
  tags: string[]
}

export default function AdminChatPage() {
  const [user, setUser] = useState<FirebaseUser | null>(null)
  const [questions, setQuestions] = useState<Question[]>([])
  const [selectedQuestion, setSelectedQuestion] = useState<Question | null>(null)
  const [answer, setAnswer] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [filterStatus, setFilterStatus] = useState('all')
  const [isLoading, setIsLoading] = useState(false)
  const [isAuthorized, setIsAuthorized] = useState(false)
  const [authLoading, setAuthLoading] = useState(true)

  const ADMIN_UID = 'HkrF6aC0tJdoTcajkH0HjctsjDg2'

  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged((u) => {
      setUser(u)
      if (u && u.uid === ADMIN_UID) {
        setIsAuthorized(true)
      } else {
        setIsAuthorized(false)
      }
      setAuthLoading(false)
    })
    return () => unsubscribe()
  }, [])

  useEffect(() => {
    // Load questions from Firebase in real-time
    if (isAuthorized) {
      const q = query(collection(db, 'questions'), orderBy('timestamp', 'desc'))
      const unsubscribe = onSnapshot(q, (snapshot) => {
        const questionsData: Question[] = []
        snapshot.forEach((doc) => {
          const data = doc.data()
          questionsData.push({
            id: doc.id,
            content: data.content,
            student: data.student,
            category: data.category,
            timestamp: data.timestamp.toDate(),
            priority: data.priority || 'medium',
            status: data.status || 'unanswered',
            likes: data.likes || 0,
            views: data.views || 0,
            tags: data.tags || []
          })
        })
        setQuestions(questionsData)
      })

      return () => unsubscribe()
    }
  }, [isAuthorized])

  const handleAnswerSubmit = async () => {
    if (!answer.trim() || !selectedQuestion || !user) return
    
    setIsLoading(true)
    
    try {
      // Create answer data
      const answerData = {
        content: answer,
        answeredBy: {
          id: user.uid,
          name: user.displayName || 'Team Lead',
          email: user.email || '',
          avatar: user.photoURL || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.displayName || 'Team Lead')}&background=059669&color=fff`
        },
        timestamp: new Date()
      }

      // Update question status and add answer
      const questionRef = doc(db, 'questions', selectedQuestion.id)
      await updateDoc(questionRef, {
        status: 'answered',
        answer: answerData
      })
      
      // Update local state
      setQuestions(prev => prev.map(q => 
        q.id === selectedQuestion.id 
          ? { ...q, status: 'answered' as const }
          : q
      ))
      
      setAnswer('')
      setSelectedQuestion(null)
      
    } catch (error) {
      console.error('Error submitting answer:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'urgent': return 'bg-red-500/20 text-red-400 border-red-500/30'
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      default: return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'answered': return 'bg-green-500/20 text-green-400 border-green-500/30'
      case 'resolved': return 'bg-purple-500/20 text-purple-400 border-purple-500/30'
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    }
  }

  const filteredQuestions = questions.filter(q => {
    const matchesSearch = q.content.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         q.student.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         q.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))
    const matchesFilter = filterStatus === 'all' || q.status === filterStatus
    return matchesSearch && matchesFilter
  })

  const stats = {
    total: questions.length,
    unanswered: questions.filter(q => q.status === 'unanswered').length,
    answered: questions.filter(q => q.status === 'answered').length,
    avgResponse: '12m'
  }

  return (
    <div className="min-h-screen bg-black text-white">
      {authLoading ? (
        <div className="flex items-center justify-center min-h-screen">
          <div className="text-center">
            <div className="w-8 h-8 border-2 border-white/30 border-t-white rounded-full animate-spin mx-auto mb-4" />
            <p className="text-zinc-400">Checking authorization...</p>
          </div>
        </div>
      ) : !isAuthorized ? (
        <div className="flex items-center justify-center min-h-screen">
          <div className="text-center max-w-md mx-auto px-4">
            <Shield className="w-16 h-16 text-red-400 mx-auto mb-4" />
            <h1 className="text-2xl font-bold text-red-400 mb-2">Access Denied</h1>
            <p className="text-zinc-400 mb-4">
              You don&apos;t have permission to access the admin dashboard. Only authorized team leads can view this page.
            </p>
            <Button 
              onClick={() => window.location.href = '/chat'}
              className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500"
            >
              Go to Student Chat
            </Button>
          </div>
        </div>
      ) : (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-gradient-to-r from-green-500 to-emerald-500 rounded-xl flex items-center justify-center">
                <Shield className="w-7 h-7 text-white" />
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-green-400 to-emerald-400 bg-clip-text text-transparent">
                  Team Lead Dashboard
                </h1>
                <p className="text-zinc-400">Manage student questions and provide expert guidance</p>
              </div>
            </div>
            
            {user && (
              <div className="flex items-center gap-3 bg-zinc-800/30 rounded-xl p-3 border border-zinc-700/50">
                <div className="w-10 h-10 rounded-lg overflow-hidden bg-gradient-to-r from-green-500 to-emerald-500">
                  <Image
                    src={user.photoURL || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.displayName || 'Team Lead')}&background=059669&color=fff`}
                    alt={user.displayName || 'Team Lead'}
                    width={40}
                    height={40}
                    className="w-full h-full object-cover"
                    unoptimized
                  />
                </div>
                <div>
                  <p className="text-sm font-semibold text-white">{user.displayName || 'Team Lead'}</p>
                  <p className="text-xs text-green-400">Expert Status</p>
                </div>
              </div>
            )}
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-zinc-800/50 rounded-lg p-4 border border-zinc-700/50">
              <div className="flex items-center gap-2 mb-2">
                <MessageCircle className="w-4 h-4 text-blue-400" />
                <span className="text-sm text-zinc-400">Total Questions</span>
              </div>
              <p className="text-2xl font-bold text-white">{stats.total}</p>
            </div>
            <div className="bg-zinc-800/50 rounded-lg p-4 border border-zinc-700/50">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span className="text-sm text-zinc-400">Unanswered</span>
              </div>
              <p className="text-2xl font-bold text-white">{stats.unanswered}</p>
            </div>
            <div className="bg-zinc-800/50 rounded-lg p-4 border border-zinc-700/50">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-sm text-zinc-400">Answered</span>
              </div>
              <p className="text-2xl font-bold text-white">{stats.answered}</p>
            </div>
            <div className="bg-zinc-800/50 rounded-lg p-4 border border-zinc-700/50">
              <div className="flex items-center gap-2 mb-2">
                <Clock className="w-4 h-4 text-purple-400" />
                <span className="text-sm text-zinc-400">Avg Response</span>
              </div>
              <p className="text-2xl font-bold text-white">{stats.avgResponse}</p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Questions List */}
          <div className="lg:col-span-2">
            <div className="bg-zinc-800/30 rounded-xl border border-zinc-700/50">
              <div className="p-4 border-b border-zinc-700/50">
                <div className="flex gap-4 mb-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-zinc-400" />
                    <Input
                      placeholder="Search questions, students, or tags..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-10 bg-zinc-800/50 border-zinc-700/50 text-white placeholder-zinc-400"
                    />
                  </div>
                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    className="px-3 py-2 bg-zinc-800/50 border border-zinc-700/50 rounded-lg text-white text-sm"
                  >
                    <option value="all">All Status</option>
                    <option value="unanswered">Unanswered</option>
                    <option value="answered">Answered</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </div>
              </div>
              
              <div className="max-h-[600px] overflow-y-auto">
                {filteredQuestions.map((question) => (
                  <div
                    key={question.id}
                    onClick={() => setSelectedQuestion(question)}
                    className={`p-4 border-b border-zinc-700/30 cursor-pointer transition-all duration-200 hover:bg-zinc-700/30 ${
                      selectedQuestion?.id === question.id ? 'bg-cyan-500/10 border-l-4 border-l-cyan-400' : ''
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className="w-10 h-10 rounded-lg overflow-hidden bg-gradient-to-r from-cyan-500 to-blue-500 flex-shrink-0">
                        <Image
                          src={question.student.avatar}
                          alt={question.student.name}
                          width={40}
                          height={40}
                          className="w-full h-full object-cover"
                          unoptimized
                        />
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-semibold text-white text-sm">{question.student.name}</span>
                          <Badge className={`text-xs ${getPriorityColor(question.priority)}`}>
                            {question.priority}
                          </Badge>
                          <Badge className={`text-xs ${getStatusColor(question.status)}`}>
                            {question.status}
                          </Badge>
                          <span className="text-xs text-zinc-400 ml-auto">
                            {question.timestamp.toLocaleDateString()}
                          </span>
                        </div>
                        
                        <p className="text-zinc-200 text-sm leading-relaxed mb-3 line-clamp-2">
                          {question.content}
                        </p>
                        
                        <div className="flex items-center gap-4 text-xs text-zinc-400">
                          <div className="flex items-center gap-1">
                            <Eye className="w-3 h-3" />
                            {question.views}
                          </div>
                          <div className="flex items-center gap-1">
                            <Star className="w-3 h-3" />
                            {question.likes}
                          </div>
                          <Badge variant="outline" className="text-xs">
                            {question.category}
                          </Badge>
                        </div>
                        
                        <div className="flex gap-1 mt-2">
                          {question.tags.slice(0, 3).map((tag, index) => (
                            <span
                              key={index}
                              className="text-xs bg-zinc-700/50 text-zinc-300 px-2 py-1 rounded"
                            >
                              #{tag}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Answer Panel */}
          <div className="lg:col-span-1">
            <div className="bg-zinc-800/30 rounded-xl border border-zinc-700/50 p-4 sticky top-4">
              {selectedQuestion ? (
                <div>
                  <div className="mb-4">
                    <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
                      <Reply className="w-5 h-5 text-green-400" />
                      Answer Question
                    </h3>
                    <div className="bg-zinc-700/30 rounded-lg p-3 mb-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-sm font-medium text-white">{selectedQuestion.student.name}</span>
                        <Badge className={`text-xs ${getPriorityColor(selectedQuestion.priority)}`}>
                          {selectedQuestion.priority}
                        </Badge>
                      </div>
                      <p className="text-sm text-zinc-200 leading-relaxed">{selectedQuestion.content}</p>
                    </div>
                  </div>
                  
                  <div className="space-y-4">
                    <Textarea
                      placeholder="Provide a detailed and helpful answer..."
                      value={answer}
                      onChange={(e) => setAnswer(e.target.value)}
                      className="bg-zinc-800/50 border-zinc-700/50 text-white placeholder-zinc-400 min-h-[200px]"
                    />
                    
                    <div className="flex gap-2">
                      <Button
                        onClick={handleAnswerSubmit}
                        disabled={!answer.trim() || isLoading}
                        className="flex-1 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500"
                      >
                        {isLoading ? (
                          <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2" />
                        ) : (
                          <Reply className="w-4 h-4 mr-2" />
                        )}
                        {isLoading ? 'Sending...' : 'Send Answer'}
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => setSelectedQuestion(null)}
                        className="border-zinc-600 text-zinc-300"
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <MessageCircle className="w-12 h-12 text-zinc-600 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-zinc-400 mb-2">Select a Question</h3>
                  <p className="text-sm text-zinc-500">Choose a question from the list to provide an answer</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      )}
    </div>
  )
}
